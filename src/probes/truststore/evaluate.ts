import { X509Certificate } from '@peculiar/x509';
import type { ObservedAnchor } from '../../engine/index.ts';
import type { Evidence, Finding, Severity } from '../../model/finding.ts';
import type {
  RuntimeStoreOutcome,
  TrustStoreCommand,
  TrustStoreFailure,
  TrustStoreKind,
  TrustStoreOutcome,
} from '../../net/types.ts';
import type { Runtime } from '../../profiles/schema.ts';
import { canonicalDn, certificateIndex } from '../shared/root-index.ts';

/**
 * The trust-store cross-check (M4, SPEC.md §7): which roots does this machine
 * trust that the runtimes on it do not, and is one of them the anchor the `tls`
 * probe just watched terminate a chain.
 *
 * Pure, in the way ADR-0002 means it: PEM strings and recorded outcomes in,
 * findings out. No I/O, no clock, no environment - every seam the answer
 * depends on (both readers, the executing runtime's own root list, the pinned
 * command table, the anchors `tls` observed) arrives on `CrossCheckInput`, so
 * the whole verdict is reproducible from a fixture. `index.ts` is the edge that
 * fills that struct in.
 *
 * `@peculiar/x509` is used here to **parse and read names only** (ADR-0021):
 * nothing below builds a chain or checks a signature. Certificate identity is
 * byte identity over DER, exactly as the `tls` probe's is, and the weaker
 * name-only comparison exists in one place - the correlation step - where it is
 * reported as the weaker match rather than passed off as proof.
 *
 * Two refusals shape the finding set, and both are about not overstating:
 *
 * 1. **A root the machine has and a runtime lacks is described factually**,
 *    never as "a corporate root". ADR-0031's lesson is that a public root
 *    merely newer than the runtime's bundled snapshot lands in the same set.
 * 2. **When no OS store could be read, no verdict is emitted at all** - not the
 *    bad one and, load-bearingly, not the good one. `osEvidenceLevel` is what
 *    decides that, and `truststore.crosscheck.indeterminate` is what says so
 *    out loud (ADR-0037).
 */

export interface CrossCheckInput {
  osStores: readonly TrustStoreOutcome[];
  runtimeStores: readonly RuntimeStoreOutcome[];
  runtimes: readonly Runtime[];
  /**
   * The executing runtime's own Mozilla list. What "public" means here - a
   * list, never a claim that two runtimes ship the same one (ADR-0031).
   */
  publicRootPems: readonly string[];
  observedAnchors: readonly ObservedAnchor[];
  /**
   * The pinned command table, for its `timeoutMs` column and nothing else.
   *
   * A timed-out outcome carries the budget it was given but not the ceiling
   * that budget was cut from, and those two numbers are what tell "the run's
   * clock bound this read" apart from "this store outran a healthy ceiling" -
   * two different sentences to an operator, one of which is a lie when written
   * for the other (ADR-0037, and the `budgetMs` doc comment on the outcome).
   * The table arrives as data rather than being imported, because importing it
   * would drag the module that starts processes into the pure half.
   */
  osCommands: readonly TrustStoreCommand[];
}

const PROBE = 'truststore';

/** Enough anchors to act on, few enough to read. The rest are counted, not listed. */
const MAX_REPORTED_DNS = 5;

/** `searched` is a customer's real paths; the plan caps what reaches a finding at five. */
const MAX_REPORTED_PATHS = 5;

/** Our own stand-in for "there was none", matching the tls probe's. Never a remote string. */
const NO_CODE = 'unavailable';

/**
 * Finding ids, written out one literal at a time (D7). They are API - customers
 * grep for them in their own CI - so none of them is built by interpolating a
 * runtime name into a template, which would make `truststore.java.missing-root`
 * impossible to find in this repo by searching for it.
 */
interface RuntimeIds {
  missingRoot: string;
  rootsPresent: string;
  platformVerifier: string;
  extraCaUnreadable: string;
  extraCaConfigured: string;
  storeNotFound: string;
}

const RUNTIME_IDS: Readonly<Record<Runtime, RuntimeIds>> = {
  node: {
    missingRoot: 'truststore.node.missing-root',
    rootsPresent: 'truststore.node.roots-present',
    platformVerifier: 'truststore.node.platform-verifier',
    extraCaUnreadable: 'truststore.node.extra-ca-unreadable',
    extraCaConfigured: 'truststore.node.extra-ca-configured',
    storeNotFound: 'truststore.node.store-not-found',
  },
  go: {
    missingRoot: 'truststore.go.missing-root',
    rootsPresent: 'truststore.go.roots-present',
    platformVerifier: 'truststore.go.platform-verifier',
    extraCaUnreadable: 'truststore.go.extra-ca-unreadable',
    extraCaConfigured: 'truststore.go.extra-ca-configured',
    storeNotFound: 'truststore.go.store-not-found',
  },
  python: {
    missingRoot: 'truststore.python.missing-root',
    rootsPresent: 'truststore.python.roots-present',
    platformVerifier: 'truststore.python.platform-verifier',
    extraCaUnreadable: 'truststore.python.extra-ca-unreadable',
    extraCaConfigured: 'truststore.python.extra-ca-configured',
    storeNotFound: 'truststore.python.store-not-found',
  },
  java: {
    missingRoot: 'truststore.java.missing-root',
    rootsPresent: 'truststore.java.roots-present',
    platformVerifier: 'truststore.java.platform-verifier',
    extraCaUnreadable: 'truststore.java.extra-ca-unreadable',
    extraCaConfigured: 'truststore.java.extra-ca-configured',
    storeNotFound: 'truststore.java.store-not-found',
  },
};

/** The kinds a *variable* names, so "set and unreadable" is a finding and "unset" is not. */
const ENV_STORE_KINDS: ReadonlySet<RuntimeStoreOutcome['kind']> = new Set([
  'node-extra-ca',
  'go-ssl-cert-file',
  'go-ssl-cert-dir',
  'python-ssl-cert-file',
  'python-requests-ca-bundle',
]);

// --- anchors ---------------------------------------------------------------

/** One parsed anchor. A store holds a few hundred of these; they are parsed once. */
interface Anchor {
  der: Uint8Array;
  /** Readable subject, emitted as `dn` evidence so redaction hashes it. */
  subject: string;
  /** Canonical subject: the sort key, and the only identity a name-only match has. */
  canonicalSubject: string;
}

/**
 * Base64 of the DER bytes, used as the identity key.
 *
 * Deliberately a local copy of `root-index.ts`'s private helper rather than a
 * new export from it: that module answers *membership* in a set, and this one
 * needs *identity*, to deduplicate two keychains holding the same root and to
 * correlate an observed anchor. Exporting the key function would invite a third
 * caller to build its own index beside the one ADR-0021 says there is exactly
 * one of.
 */
function derKey(der: Uint8Array): string {
  let binary = '';
  // Chunked for the reason `root-index.ts` gives: spreading every byte as an
  // argument is a stack overflow waiting for a large certificate.
  for (let offset = 0; offset < der.length; offset += 0x2000) {
    binary += String.fromCharCode(...der.subarray(offset, offset + 0x2000));
  }
  return btoa(binary);
}

/** One store's anchors, and what it held that never became one. */
interface StoreAnchors {
  anchors: Map<string, Anchor>;
  /**
   * Blocks that did not parse. The readers already drop everything that is not
   * a base64 `CERTIFICATE` block, so what arrives here and still fails is a
   * malformed certificate in the customer's own store - and throwing over it
   * would take the whole report down.
   *
   * It is *counted* rather than merely skipped because the skip is load-bearing
   * in the wrong direction: an anchor that fails to parse leaves `locallyAdded`
   * silently, and if it was the one a runtime lacks, that runtime gets a clean
   * `roots-present`. In the limit an entirely unparsable store reads as
   * "0 anchors, nothing missing" - a clean bill for every runtime on the
   * machine. The count rides on `truststore.os.read` so the number an operator
   * reads there is the number portcall actually cross-checked.
   */
  unparsed: number;
}

/** Parse one store's PEMs into anchors, deduplicated by DER. */
function anchorsOf(pems: readonly string[]): StoreAnchors {
  const anchors = new Map<string, Anchor>();
  let unparsed = 0;
  for (const pem of pems) {
    let certificate: X509Certificate;
    try {
      certificate = new X509Certificate(pem);
    } catch {
      unparsed += 1;
      continue;
    }
    const der = new Uint8Array(certificate.rawData);
    const key = derKey(der);
    if (anchors.has(key)) continue;
    anchors.set(key, { der, subject: certificate.subject, canonicalSubject: canonicalDn(certificate.subjectName) });
  }
  return { anchors, unparsed };
}

/** Deterministic order for everything the report prints: by canonical subject. */
function byCanonicalSubject(left: Anchor, right: Anchor): number {
  if (left.canonicalSubject < right.canonicalSubject) return -1;
  return left.canonicalSubject > right.canonicalSubject ? 1 : 0;
}

// --- the OS half -----------------------------------------------------------

/**
 * How much of this machine's trust store portcall actually saw (ADR-0037).
 *
 * The cross-check is a statement about a *set*, so how much of that set is
 * known changes what may be said about it: at `none` the locally-added set is
 * undefined rather than empty, and an undefined set may not produce a clean
 * verdict any more than a dirty one.
 */
export type OsEvidenceLevel = 'complete' | 'partial' | 'none';

export function osEvidenceLevel(osStores: readonly TrustStoreOutcome[]): OsEvidenceLevel {
  const read = osStores.filter((store) => store.failure === null).length;
  if (read === 0) return 'none';
  return read === osStores.length ? 'complete' : 'partial';
}

/**
 * How much of this machine's trust store portcall saw, in the one shape
 * `crossCheck` computes once and threads through - `runtimeFindings` used to
 * recompute `read`/`unread` itself on every call, which is how a future edit
 * to one copy silently stops matching the other.
 */
export interface OsCoverage {
  level: OsEvidenceLevel;
  read: number;
  unread: number;
  /** Run total, across every store - unlike `truststore.os.read`'s own count, which is per store. */
  unparsed: number;
}

function osCoverage(
  osStores: readonly TrustStoreOutcome[],
  anchorsPerStore: ReadonlyMap<TrustStoreOutcome, StoreAnchors>,
): OsCoverage {
  const read = osStores.filter((store) => store.failure === null).length;
  let unparsed = 0;
  for (const parsed of anchorsPerStore.values()) unparsed += parsed.unparsed;
  return { level: osEvidenceLevel(osStores), read, unread: osStores.length - read, unparsed };
}

/** The row's healthy-read ceiling for this store, or null when the table has no row for it. */
function ceilingFor(kind: TrustStoreKind, commands: readonly TrustStoreCommand[]): number | null {
  return commands.find((command) => command.kind === kind)?.timeoutMs ?? null;
}

/** Whole seconds where the number is whole, one decimal where it is not. */
function seconds(ms: number): string {
  const value = ms / 1000;
  return Number.isInteger(value) ? String(value) : value.toFixed(1);
}

/**
 * What an operator does about a store that ran out of time - and the two
 * answers are opposites, so they may not share a sentence (ADR-0037).
 *
 * `--timeout` is the run's deadline, and the reader's budget is the *smaller*
 * of what remains of that deadline and the row's own ceiling. So "re-run with
 * --timeout raised" is true exactly when the deadline was the smaller of the
 * two, and is a lie when the row's ceiling was: portcall exposes no knob for
 * the row, and a machine that outran a healthy ceiling has already told us the
 * thing we wanted to know.
 */
function readTimeoutRemediation(store: TrustStoreOutcome, ceiling: number | null): string {
  // `budget-exhausted` needs no comparison against the row: the code already
  // says the run's own clock was what ran out, and no child was started to have
  // been given a budget at all.
  if (store.code === 'budget-exhausted') {
    return (
      "The run's remaining time ran out before this store was read, not the store itself: the " +
      'four earlier probes used the whole budget. Re-run with --timeout raised (default 60 ' +
      'seconds, and truststore runs last).'
    );
  }

  const applied = store.budgetMs ?? 0;
  const rowBound = ceiling !== null && applied >= ceiling;
  return (
    `Portcall stopped reading ${store.locator} after ${seconds(applied)} seconds, so the ` +
    'trust-store cross-check below is incomplete rather than clean - do not read it as "this ' +
    'root is present". ' +
    (rowBound
      ? 'That is the whole time this store gets on this platform rather than a slice of the run ' +
        "budget: the run's own --timeout is not what cut the read short, so raising it would " +
        'only wait longer for the same answer. The ceiling is what a healthy host of this ' +
        'platform actually needs for this read, with headroom above it, so a store that outruns ' +
        'it is the finding rather than a number to retune. '
      : 'The run had less time left than this store is allowed, so the run budget is what cut ' +
        'the read short: re-run with --timeout raised to give it more room. ') +
    "If it still does not finish, list that store with your platform's own certificate tool and " +
    'send the output with this report. On Windows, a first enumeration of the machine root store ' +
    'can also block while the OS itself fetches its root-certificate update list, so check ' +
    'whether ctldl.windowsupdate.com is reachable or blocked at your egress.'
  );
}

function readTimeoutFinding(store: TrustStoreOutcome, ceiling: number | null): Finding {
  const evidence: Evidence[] = [
    { label: 'store', value: store.kind, kind: 'text' },
    { label: 'store read', value: store.locator, kind: 'path' },
  ];
  // Zero means no child was started, so it is not a duration anything got:
  // printing it under "budget applied" would tell a reader the store was read
  // for no time rather than not read at all. The row's ceiling is what is worth
  // showing in its place, and the code beside it says why it went unused.
  if (store.budgetMs !== null && store.budgetMs > 0) {
    evidence.push({ label: 'budget applied (ms)', value: String(store.budgetMs), kind: 'number' });
  } else if (ceiling !== null) {
    evidence.push({ label: 'store budget, never applied (ms)', value: String(ceiling), kind: 'number' });
  }
  // What the failure itself cannot say. `timeout` means "at least the budget",
  // and whether the store missed it by a second or was nowhere near answering
  // is the difference between a ceiling worth revising and a machine worth
  // asking about (ADR-0039). Absent on the branch where no read was started,
  // for the same reason the applied budget is.
  if (store.readMs !== null) {
    evidence.push({ label: 'read took (ms)', value: String(store.readMs), kind: 'number' });
  }
  evidence.push({ label: 'code', value: store.code ?? NO_CODE, kind: 'text' });

  return {
    id: 'truststore.os.read-timeout',
    probe: PROBE,
    // `unknown`, matching `truststore.os.unreadable`: it rolls up non-zero, so
    // a store that was never read can never be mistaken for one that was read
    // and was clean.
    severity: 'unknown',
    title: 'Reading this machine’s trust store did not finish inside the time allowed',
    evidence,
    remediation: readTimeoutRemediation(store, ceiling),
  };
}

/** Shared between the three "it ran and produced nothing usable" rows; the empty-store row differs. */
const STORE_UNREADABLE_TITLE = 'Portcall could not read this machine’s trust store';
const STORE_EMPTY_TITLE = 'Portcall read this machine’s trust store and it held no certificates';

/**
 * Why a store read produced nothing, one row per `TrustStoreFailure` a reader
 * can actually emit (`timeout` and `aborted` have their own findings above;
 * `unsupported-platform` is never assigned to a store - it is synthesised by
 * `unsupportedPlatformFinding` from an *empty* `osStores` array). Four
 * distinct remediations, because "the tool was not there to run" and "the
 * tool ran and did not answer" send an operator to two different places, and
 * "ran clean and held nothing" is not a read failure at all - CLAUDE.md's
 * rule against collapsing operationally distinct errors, applied to a table
 * instead of a switch (ADR-precedent: `probe-error.ts`'s
 * `switch-exhaustiveness-check` note).
 */
const OS_READ_FAILURES: Readonly<
  Record<Exclude<TrustStoreFailure, 'unsupported-platform' | 'timeout' | 'aborted'>, { title: string; remediation: string }>
> = {
  'reader-missing': {
    title: STORE_UNREADABLE_TITLE,
    remediation:
      'The tool this platform lists certificates with was not there to run - the absolute path portcall ' +
      'pins it to (ADR-0033) does not exist on this machine. Confirm it is installed where this platform ' +
      'ships it, or list the store yourself with the platform’s certificate manager and send the output ' +
      'with this report.',
  },
  'reader-failed': {
    title: STORE_UNREADABLE_TITLE,
    remediation:
      'The tool this platform lists certificates with ran and did not answer - the code above says whether ' +
      'it exited non-zero or was killed by a signal portcall did not send. Run the same listing yourself to ' +
      'see what it reports, or list the store with the platform’s certificate manager and send the output ' +
      'with this report.',
  },
  'output-too-large': {
    title: STORE_UNREADABLE_TITLE,
    remediation:
      'This store’s listing exceeded the size portcall reads from a child process, and the child was killed ' +
      'before it printed the rest, so nothing from it could be parsed. That is unusual for a trust store; ' +
      'list it yourself with the platform’s certificate manager to see what is actually in it, and send the ' +
      'output with this report.',
  },
  'no-certificates': {
    title: STORE_EMPTY_TITLE,
    remediation:
      'Portcall read this store and it held no certificates at all, which is unusual for a trust store, so ' +
      'the cross-check below has nothing to compare runtimes against for it. Confirm this is really the ' +
      'store this machine verifies TLS connections against with the platform’s certificate manager - an ' +
      'empty result more often means the wrong path than an empty machine.',
  },
};

/**
 * A store that failed for one of `OS_READ_FAILURES`' four reasons. Per store,
 * never aggregated (ADR material this WP writes up): the suppression this
 * replaces hid every runtime verdict behind one store that happened to fail
 * first (session 24's live defect). Each row still names its own store, so a
 * machine with five clean keychains and one broken one gets one finding
 * naming the broken one, not five green verdicts withheld because of it.
 */
function unreadableFinding(store: TrustStoreOutcome): Finding {
  const failure = store.failure;
  // The caller (`osFindings`' switch) only reaches this branch after
  // excluding null/timeout/aborted/unsupported-platform, so this narrows to
  // exactly `OS_READ_FAILURES`'s four keys. The guard below is for the
  // compiler, which only knows the field's full declared type - the same
  // idiom `tls/evaluate.ts`'s `anchorOf` uses.
  if (failure === null || failure === 'timeout' || failure === 'aborted' || failure === 'unsupported-platform') {
    /* c8 ignore next */
    throw new Error(`unreadableFinding called with a failure it does not cover: ${String(failure)}`);
  }
  const { title, remediation } = OS_READ_FAILURES[failure];
  return {
    id: 'truststore.os.unreadable',
    probe: PROBE,
    severity: 'unknown',
    title,
    evidence: [
      { label: 'store', value: store.kind, kind: 'text' },
      { label: 'store read', value: store.locator, kind: 'path' },
      { label: 'failure', value: failure, kind: 'text' },
      { label: 'code', value: store.code ?? NO_CODE, kind: 'text' },
    ],
    remediation,
  };
}

/**
 * The one case `unreadableFinding` cannot cover: no reader ran at all,
 * because the platform is none of darwin, win32 or linux. `osStores` is then
 * empty by `OsTrustStoreReader.read`'s own postcondition, so there is no
 * per-store `failure` to report - this is the whole cross-check's reference
 * set, missing.
 */
function unsupportedPlatformFinding(): Finding {
  return {
    id: 'truststore.os.unreadable',
    probe: PROBE,
    severity: 'unknown',
    title: 'Portcall has no trust-store reader for this operating system',
    evidence: [{ label: 'failure', value: 'unsupported-platform', kind: 'text' }],
    remediation:
      'Portcall reads the trust store on macOS, Windows and Linux, and this machine is none of ' +
      'them, so it did not look rather than looking and finding nothing. The cross-check below ' +
      'is missing its entire reference set: list this machine’s roots with whatever tool this ' +
      'platform provides and compare them by hand against the runtime stores named below.',
  };
}

/**
 * What an operator does about a store that held blocks which never became an
 * anchor: this is the same "counted, not dropped in silence" rule
 * `StoreAnchors.unparsed`'s own doc gives, said out loud on the finding an
 * operator actually reads.
 */
function unparsedRemediation(count: number): string {
  return (
    `This store held ${count} block${count === 1 ? '' : 's'} that did not parse as a certificate - a ` +
    'malformed entry in this machine’s own trust store, not something portcall can fix. Every check ' +
    'below is against the anchors that did parse; if the root you expect to find is missing from ' +
    'them, it may be the one that failed to parse. List the store yourself with the platform’s ' +
    'certificate manager to confirm.'
  );
}

/**
 * Findings about the stores themselves, before anything is cross-checked
 * against them.
 *
 * `locallyAddedKeys` is the run-wide set, but the count printed here is this
 * store's share of it: the finding is per store, so a run-wide total under a
 * keychain holding one anchor prints a subset larger than the set it sits
 * inside.
 */
function osFindings(
  input: CrossCheckInput,
  anchorsPerStore: Map<TrustStoreOutcome, StoreAnchors>,
  locallyAddedKeys: ReadonlySet<string>,
): Finding[] {
  const findings: Finding[] = [];

  for (const store of input.osStores) {
    switch (store.failure) {
      case null: {
        const parsed = anchorsPerStore.get(store);
        const anchors = parsed === undefined ? [] : [...parsed.anchors.values()];
        const locallyAdded = anchors.filter((anchor) => locallyAddedKeys.has(derKey(anchor.der))).length;
        const unparsed = parsed === undefined ? 0 : parsed.unparsed;
        findings.push({
          id: 'truststore.os.read',
          probe: PROBE,
          severity: 'ok',
          title: 'Read this machine’s trust store',
          evidence: [
            { label: 'store', value: store.kind, kind: 'text' },
            { label: 'store read', value: store.locator, kind: 'path' },
            // On the clean read too, not only on the timeout: a store that
            // answers in 30 s is the one worth knowing about before it stops
            // answering at all.
            ...(store.readMs === null
              ? []
              : [{ label: 'read took (ms)', value: String(store.readMs), kind: 'number' as const }]),
            { label: 'anchors', value: String(anchors.length), kind: 'number' },
            { label: 'locally added', value: String(locallyAdded), kind: 'number' },
            // Only when there were any: a zero on every clean read is noise, and
            // a non-zero one is the difference between "this store holds two
            // anchors" and "this store holds two portcall could read".
            ...(unparsed > 0 ? [{ label: 'unparsable certificates', value: String(unparsed), kind: 'number' as const }] : []),
          ],
          ...(unparsed > 0 ? { remediation: unparsedRemediation(unparsed) } : {}),
        });
        continue;
      }
      case 'timeout':
        findings.push(readTimeoutFinding(store, ceilingFor(store.kind, input.osCommands)));
        continue;
      case 'aborted':
        findings.push({
          id: 'truststore.os.aborted',
          probe: PROBE,
          severity: 'unknown',
          title: 'The run ended before this machine’s trust store was read',
          evidence: [
            { label: 'store', value: store.kind, kind: 'text' },
            { label: 'store read', value: store.locator, kind: 'path' },
          ],
          // Says nothing about the machine, deliberately: a cancelled run learned
          // nothing about this store, and a remediation that blamed the
          // environment would be a false statement about a customer's laptop.
          remediation:
            'The run was cancelled before this store was read, so nothing here is a verdict about ' +
            'the store or about this machine - the read simply never happened. Re-run without ' +
            'interrupting it, and with a larger --timeout if the run hit its own budget.',
        });
        continue;
      case 'unsupported-platform':
        // Never true of a real store: `types.ts`'s own doc says this value is
        // synthesised by the probe from an *empty* `osStores` array, never
        // assigned by a reader. Listed explicitly, doing nothing, so that
        // `@typescript-eslint/switch-exhaustiveness-check` keeps every branch
        // below this one - `OS_READ_FAILURES`'s four keys - honest rather than
        // silently swallowed by a `default`.
        continue;
      case 'reader-missing':
      case 'reader-failed':
      case 'output-too-large':
      case 'no-certificates':
        findings.push(unreadableFinding(store));
        continue;
    }
  }

  // The reader's postcondition: an empty array is *exactly* a platform that is
  // none of darwin, win32 or linux, and the probe is the only place that word
  // is spoken (FLAG 1). No aggregate for anything else any more - each failed
  // store already named itself above, per store, per failure class.
  if (input.osStores.length === 0) findings.push(unsupportedPlatformFinding());

  return findings;
}

// --- trust sets ------------------------------------------------------------

/**
 * The set of roots one runtime actually consults, as one store or a union of
 * them (D9). A runtime can have several: java gets one per discovered JDK,
 * because a root present in one and missing from another is a real finding that
 * unioning them would hide.
 */
interface TrustSet {
  runtime: Runtime;
  /** The store this set is, where it has a single one. Null for a bundle or a union. */
  locator: string | null;
  pems: readonly string[];
  /**
   * True when a store this set was built from was read only in part - a
   * keystore some of whose bags are password-protected (`RuntimeStoreOutcome.partial`).
   * The set is then a subset of what the runtime actually consults, which is
   * enough to say a root is missing from what was read and never enough to say
   * every root is present.
   */
  partial: boolean;
}

/**
 * Group one runtime's outcomes into the sets it consults.
 *
 * `replaces` shadows the default set (`REQUESTS_CA_BUNDLE` really does replace
 * certifi for `requests`), `adds-to` unions into every default set
 * (`NODE_EXTRA_CA_CERTS` is appended to Node's bundle, not swapped for it), and
 * each `standalone` store is a set of its own. Only stores that were actually
 * *read* take part: a variable naming an unreadable file is one the runtime
 * ignores in silence, so the set it would have replaced is still the live one -
 * and `extra-ca-unreadable` is what tells the operator that.
 */
function trustSets(runtime: Runtime, outcomes: readonly RuntimeStoreOutcome[]): TrustSet[] {
  const readable = outcomes.filter((outcome) => outcome.failure === null && outcome.kind !== 'platform-verifier');
  const additions = readable.filter((outcome) => outcome.combines === 'adds-to');
  const additionPems = additions.flatMap((outcome) => outcome.pems);
  const additionsPartial = additions.some((outcome) => outcome.partial);
  const replacing = readable.filter((outcome) => outcome.combines === 'replaces');
  const bases = replacing.length > 0 ? replacing : readable.filter((outcome) => outcome.combines === 'standalone');
  return bases.map((base) => ({
    runtime,
    locator: base.locator,
    pems: [...base.pems, ...additionPems],
    partial: base.partial || additionsPartial,
  }));
}

// --- correlation -----------------------------------------------------------

/** How an observed anchor was tied to a missing one. Two strengths, never conflated. */
type MatchStrength = 'bytes' | 'issuer-name';

interface Correlation {
  anchor: ObservedAnchor;
  match: MatchStrength;
  /** The `missing` anchor this correlation ties to, so it can be moved ahead of the `MAX_REPORTED_DNS` truncation (Bug 4). */
  matched: Anchor;
}

/**
 * Tie a missing anchor to a chain the `tls` probe actually watched terminate
 * (ADR-0034). Byte identity is proof; an issuer DN that merely *matches* the
 * missing anchor's subject is the weaker claim available when the peer sent no
 * root at all, and it is reported as the weaker claim rather than rounded up.
 */
function correlate(missing: readonly Anchor[], observed: readonly ObservedAnchor[]): Correlation | null {
  const byDerKey = new Map(missing.map((anchor) => [derKey(anchor.der), anchor]));
  for (const anchor of observed) {
    if (anchor.der === null) continue;
    const matched = byDerKey.get(derKey(anchor.der));
    if (matched !== undefined) return { anchor, match: 'bytes', matched };
  }
  // The name-only pass keys on `private`, and only it. `indeterminate` is the
  // `tls` probe saying it could not tell a private anchor from a public one -
  // routinely a public root re-issued under the same subject DN, which a
  // machine trusts and a runtime's older bundled snapshot does not - so a DN
  // that merely matches a maybe is not evidence that this chain is the one
  // failing, and must not carry a missing root up to `blocker`. The byte pass
  // above needs no such filter: byte identity is proof whatever it was graded.
  const bySubject = new Map(missing.map((anchor) => [anchor.canonicalSubject, anchor]));
  for (const anchor of observed) {
    if (anchor.anchorClass !== 'private') continue;
    const matched = bySubject.get(anchor.canonicalIssuer);
    if (matched !== undefined) return { anchor, match: 'issuer-name', matched };
  }
  return null;
}

// --- the runtime half ------------------------------------------------------

/** Per runtime, how an operator lists a store by hand to confirm a finding built on a partial read. */
const CONFIRM_LISTING_HINT: Readonly<Record<Runtime, string>> = {
  node: 'the file NODE_EXTRA_CA_CERTS names',
  go: 'the platform’s own certificate manager, or SSL_CERT_FILE/SSL_CERT_DIR if either is set',
  python: 'the certifi bundle or REQUESTS_CA_BUNDLE named above',
  java: '`keytool -list -keystore <path>`',
};

function missingRootRemediation(runtime: Runtime, correlation: Correlation | null, partial: boolean): string {
  const observed =
    correlation === null
      ? ''
      : correlation.match === 'bytes'
        ? 'The chain this run captured from the host above ended in this exact certificate, so ' +
          'connections from this runtime fail today rather than hypothetically. '
        : 'The chain this run captured from the host above was issued by an authority with this ' +
          'name, though the peer never sent the root itself - the match is by name and not by ' +
          'bytes, so confirm it before acting on it. ';

  // Narrows the same claim `set.partial` narrows the severity for: a chain
  // that matched a set built from an incomplete read is real evidence, but
  // not evidence that survives an unread half turning out to hold the anchor
  // after all - so before treating it as broken, list the store by hand.
  const confirmPartial =
    correlation !== null && partial
      ? `This runtime’s store was only read in part, so confirm with ${CONFIRM_LISTING_HINT[runtime]} ` +
        'before treating this as broken. '
      : '';

  switch (runtime) {
    case 'node':
      return (
        observed +
        confirmPartial +
        'Node does not read this machine’s OS trust store, so a root the machine trusts is ' +
        'invisible to it. Export the root named above from the store in the evidence - the ' +
        'platform’s own certificate manager will export it - and point Node at the file with ' +
        'NODE_EXTRA_CA_CERTS, which Node adds to its bundle rather than replacing it. On Linux, ' +
        '`node --use-openssl-ca` is an alternative, because there the OpenSSL store is the ' +
        'system bundle.'
      );
    case 'go':
      return (
        observed +
        confirmPartial +
        'Go reads the file or directory SSL_CERT_FILE and SSL_CERT_DIR name rather than this ' +
        'machine’s OS trust store whenever either is set, and the set named above does not ' +
        'hold this root. Append the root to that file, or unset both variables on macOS and ' +
        'Windows, where Go asks the operating system directly instead.'
      );
    case 'python':
      return (
        observed +
        confirmPartial +
        'requests and most Python HTTP clients read certifi’s bundle, not this machine’s OS ' +
        'store. Point them at the root with REQUESTS_CA_BUNDLE (or SSL_CERT_FILE for ssl and ' +
        'urllib), or append it to the certifi bundle named above.'
      );
    case 'java':
      return (
        observed +
        confirmPartial +
        'This JDK’s cacerts does not contain the anchor above, so anything running on it will ' +
        'fail to verify. Import it with `keytool -importcert -cacerts -alias <name> -file ' +
        'root.pem` (JDK 9+), or point the JVM at a different store with the trustStore system ' +
        'property. The path in the evidence above is the store that was read.'
      );
  }
}

/** One clustered finding per trust set, never one per anchor: a set is one ticket. */
function missingRootFinding(set: TrustSet, missing: readonly Anchor[], correlation: Correlation | null): Finding {
  const evidence: Evidence[] = [{ label: 'missing anchors', value: String(missing.length), kind: 'number' }];
  // Bug 4: the correlated anchor - the one a live chain actually tied to this
  // broken store - goes to the front before the report caps out at
  // `MAX_REPORTED_DNS`, so it is never silently outvoted by alphabetically
  // earlier anchors that carry no evidence at all. Everything else keeps its
  // alphabetical order.
  const ordered =
    correlation === null
      ? missing
      : [correlation.matched, ...missing.filter((anchor) => anchor !== correlation.matched)];
  for (const anchor of ordered.slice(0, MAX_REPORTED_DNS)) {
    evidence.push({ label: 'anchor', value: anchor.subject, kind: 'dn' });
  }
  if (set.locator !== null) evidence.push({ label: 'runtime store', value: set.locator, kind: 'path' });
  // Narrows the claim to what was read: these anchors are missing from the part
  // of the store portcall could open, and the store's own finding beside this
  // one says which part that was.
  if (set.partial) evidence.push({ label: 'runtime store read', value: 'partial', kind: 'text' });
  if (correlation !== null) {
    evidence.push({ label: 'host', value: correlation.anchor.host, kind: 'hostname' });
    evidence.push({ label: 'connection', value: correlation.anchor.via, kind: 'text' });
    evidence.push({ label: 'match', value: correlation.match, kind: 'text' });
  }

  // D4: a profile that tolerates interception does **not** soften this. That
  // setting says "an inspecting proxy is expected here", not "a root this
  // runtime cannot verify against is fine" - the runtime still fails.
  //
  // Written inline rather than through `cap()`: `cap()`'s `required` means
  // *profile* requiredness (ADR-0029), and this narrowing is about evidence
  // completeness instead - a chain observed against a set built from an
  // incomplete read is real, but not proof strong enough to call a blocker
  // when the unread half of that same set could hold the anchor after all.
  const severity: Severity = correlation === null || set.partial ? 'degraded' : 'blocker';

  return {
    id: RUNTIME_IDS[set.runtime].missingRoot,
    probe: PROBE,
    severity,
    title:
      correlation === null
        ? 'This runtime does not trust a root this machine trusts'
        : 'This runtime does not trust the root that terminated a chain it was served',
    evidence,
    remediation: missingRootRemediation(set.runtime, correlation, set.partial),
  };
}

function rootsPresentFinding(set: TrustSet, coverage: OsCoverage): Finding {
  const evidence: Evidence[] = [];
  if (set.locator !== null) evidence.push({ label: 'runtime store', value: set.locator, kind: 'path' });
  evidence.push({ label: 'anchors checked', value: String(set.pems.length), kind: 'number' });
  // Under `partial` the claim is narrower than it reads, so the counts travel
  // with it: this set holds every anchor portcall *could read*, and the unread
  // store's own finding sits beside this one saying what it could not.
  if (coverage.level === 'partial') {
    evidence.push({ label: 'stores read', value: String(coverage.read), kind: 'number' });
    evidence.push({ label: 'stores unread', value: String(coverage.unread), kind: 'number' });
  }
  // Same reason `truststore.os.read` carries the count: this "every root is
  // trusted" claim is only as good as what portcall could parse, run-wide.
  if (coverage.unparsed > 0) {
    evidence.push({ label: 'unparsable in OS store', value: String(coverage.unparsed), kind: 'number' });
  }
  return {
    id: RUNTIME_IDS[set.runtime].rootsPresent,
    probe: PROBE,
    severity: 'ok',
    title: 'This runtime trusts every root this machine adds',
    evidence,
  };
}

function extraCaFindings(runtime: Runtime, outcome: RuntimeStoreOutcome): Finding[] {
  const ids = RUNTIME_IDS[runtime];
  // Unset is a statement about the environment, not a fault: the runtime falls
  // back to the store it ships with, which is cross-checked below like any
  // other.
  if (outcome.failure === 'not-configured') return [];
  const store: Evidence[] = [
    { label: 'store', value: outcome.kind, kind: 'text' },
    ...(outcome.locator === null ? [] : [{ label: 'runtime store', value: outcome.locator, kind: 'path' as const }]),
  ];

  if (outcome.failure === null) {
    return [
      {
        id: ids.extraCaConfigured,
        probe: PROBE,
        severity: 'ok',
        title: 'The extra certificate file this runtime is pointed at was read',
        evidence: [...store, { label: 'anchors', value: String(outcome.pems.length), kind: 'number' }],
      },
    ];
  }

  // Two failures, two tickets, one id: the file could not be read, or it was
  // read and held no certificate. The runtime ignores both in the same silence,
  // which is why they share a finding - and they take different actions, which
  // is why they do not share a remediation.
  const empty = outcome.failure === 'no-certificates';
  return [
    {
      id: ids.extraCaUnreadable,
      probe: PROBE,
      severity: 'degraded',
      title: empty
        ? 'The certificate file this runtime is pointed at holds no certificate'
        : 'The certificate file this runtime is pointed at cannot be read',
      evidence: [
        ...store,
        { label: 'failure', value: outcome.failure, kind: 'text' },
        ...(outcome.code === null ? [] : [{ label: 'code', value: outcome.code, kind: 'text' as const }]),
      ],
      remediation: empty
        ? 'The variable above names a file portcall read and found no certificate in, and the ' +
          'runtime ignores that as silently as it ignores an unreadable one - the roots you ' +
          'believe are loaded are not. Check that the file holds PEM certificate blocks rather ' +
          'than a DER file, a key, or an empty placeholder.'
        : 'The variable above names a file this process cannot read, and the runtime ignores an ' +
          'unreadable value without warning - the roots you believe are loaded are not. Fix the ' +
          'path or the permissions, or unset the variable so the runtime falls back to the store ' +
          'it ships with.',
    },
  ];
}

/** Where to look next, per runtime, when nothing was found. Ours, never a PATH lookup. */
const STORE_NOT_FOUND_HINT: Readonly<Record<Runtime, string>> = {
  node: 'point NODE_EXTRA_CA_CERTS at the bundle it reads',
  go: 'set SSL_CERT_FILE or SSL_CERT_DIR',
  python: 'set VIRTUAL_ENV or REQUESTS_CA_BUNDLE',
  java: 'set JAVA_HOME',
};

function storeNotFoundFinding(runtime: Runtime, searched: readonly string[]): Finding {
  return {
    id: RUNTIME_IDS[runtime].storeNotFound,
    probe: PROBE,
    severity: 'unknown',
    title: 'No trust store was found for a runtime this profile declares',
    evidence: searched.slice(0, MAX_REPORTED_PATHS).map((path) => ({ label: 'searched', value: path, kind: 'path' })),
    remediation:
      'Portcall does not execute a toolchain it finds on PATH (ADR-0033), so it looked only in ' +
      'the well-known locations listed above and in the variables this runtime reads. Nothing ' +
      'was there, so no cross-check ran for it and this report says nothing either way about ' +
      `what it trusts. If the runtime is installed elsewhere, ${STORE_NOT_FOUND_HINT[runtime]} and ` +
      're-run; if it is not installed at all, drop it from the profile’s `runtimes` list so the ' +
      'report stops asking.',
  };
}

/**
 * A keystore that produced no usable set, or only part of one.
 *
 * The partial branch is the same fact as `encrypted`, one bag at a time: some
 * entries came back and others are password-protected. It arrives with
 * `failure: null`, so without this branch it would say nothing at all while
 * the readable half went on to be graded as if it were the whole store.
 */
function javaStoreUnreadableFinding(outcome: RuntimeStoreOutcome): Finding {
  const encrypted = outcome.failure === 'encrypted';
  const partial = outcome.failure === null && outcome.partial;
  return {
    id: 'truststore.java.store-unreadable',
    probe: PROBE,
    severity: 'unknown',
    title: partial
      ? 'Only part of this JDK’s keystore could be read: some entries are password-protected'
      : encrypted
        ? 'This JDK’s keystore is password-protected, and portcall supplies no password'
        : 'This JDK’s keystore was found and could not be read',
    evidence: [
      ...(outcome.locator === null ? [] : [{ label: 'runtime store', value: outcome.locator, kind: 'path' as const }]),
      { label: 'format', value: outcome.format ?? NO_CODE, kind: 'text' },
      { label: 'failure', value: outcome.failure ?? (partial ? 'encrypted-entries' : 'no-certificates'), kind: 'text' },
      ...(partial ? [{ label: 'anchors read', value: String(outcome.pems.length), kind: 'number' as const }] : []),
    ],
    remediation: partial
      ? 'Portcall read the certificate entries this keystore does not protect with a password and ' +
        'could not read the rest, because it never supplies a keystore password (SPEC.md §4.2, ' +
        'ADR-0036). The cross-check below therefore covers only the entries it could open, and no ' +
        'clean verdict was produced for this store: the anchors it could not read may well be the ' +
        'ones you are looking for. Run `keytool -list -keystore <path>` yourself against the store ' +
        'named above and compare the full listing against the anchors in this report.'
      : encrypted
        ? 'This cacerts is a PKCS#12 keystore whose certificate entries are password-protected. ' +
          'Portcall never supplies a keystore password (SPEC.md §4.2, ADR-0036), so it cannot ' +
          'list them. Run `keytool -list -keystore <path>` yourself against the store named above ' +
          'and compare the output against the anchors listed in this report.'
        : 'Portcall found this JDK’s keystore and could not read it - the failure class above ' +
          'says whether the container was a format it does not parse, the file was truncated, or ' +
          'the read itself failed. No missing-root verdict was produced for this store, because an ' +
          'unreadable store must manufacture neither a clean answer nor a dirty one. Run `keytool ' +
          '-list -keystore <path>` against the path above and compare it against the anchors in ' +
          'this report.',
  };
}

/**
 * Everything one runtime's outcomes say, whether or not there are OS anchors to
 * compare them against. Only the two *verdicts* - `missing-root` and
 * `roots-present` - depend on the OS half; a keystore that cannot be read and a
 * variable pointing at a missing file are facts about this machine either way.
 */
function runtimeFindings(
  runtime: Runtime,
  outcomes: readonly RuntimeStoreOutcome[],
  locallyAdded: readonly Anchor[],
  input: CrossCheckInput,
  coverage: OsCoverage,
): Finding[] {
  const findings: Finding[] = [];

  for (const outcome of outcomes) {
    if (ENV_STORE_KINDS.has(outcome.kind)) findings.push(...extraCaFindings(runtime, outcome));
    if (
      outcome.kind === 'java-cacerts' &&
      (outcome.partial || (outcome.failure !== null && outcome.failure !== 'not-found'))
    ) {
      findings.push(javaStoreUnreadableFinding(outcome));
    }
  }

  // D9: where the runtime asks the OS itself there is no second store to
  // compare, and a missing-root finding would be portcall lying about go on two
  // of its three target platforms.
  if (outcomes.some((outcome) => outcome.kind === 'platform-verifier')) {
    findings.push({
      id: RUNTIME_IDS[runtime].platformVerifier,
      probe: PROBE,
      severity: 'ok',
      title: 'This runtime asks the operating system, so it trusts what this machine trusts',
      evidence: [{ label: 'store', value: 'platform-verifier', kind: 'text' }],
    });
    return findings;
  }

  const sets = trustSets(runtime, outcomes);
  if (sets.length === 0) {
    // Nothing was located at all - as against located and unreadable, which the
    // findings above have already reported and which must not be described as
    // "not found".
    const located = outcomes.some((outcome) => outcome.failure !== 'not-configured' && outcome.failure !== 'not-found');
    if (!located) {
      findings.push(storeNotFoundFinding(runtime, outcomes.flatMap((outcome) => [...outcome.searched])));
    }
    return findings;
  }

  // The load-bearing suppression (ADR-0037): with no OS store read the
  // locally-added set is *undefined*, and a `roots-present` built on an
  // undefined set is a green finding standing on no evidence at all.
  if (coverage.level === 'none') return findings;

  for (const set of sets) {
    const index = certificateIndex([...set.pems]);
    const missing = locallyAdded.filter((anchor) => !index.hasCertificate(anchor.der));
    if (missing.length > 0) {
      findings.push(missingRootFinding(set, missing, correlate(missing, input.observedAnchors)));
      continue;
    }
    // The same suppression `coverage.level === 'none'` performs above, one
    // store down: "this runtime trusts every root this machine adds" is a
    // claim about the whole set, and a set assembled from a store read in
    // part is not the whole set. The unread entries could hold anything, so
    // the honest answer is the store's own `store-unreadable` finding and no
    // verdict here.
    if (!set.partial) findings.push(rootsPresentFinding(set, coverage));
  }
  return findings;
}

// --- the cross-check -------------------------------------------------------

/**
 * The whole verdict, in the order a reader needs it: what this machine holds,
 * then what each runtime it declares does with that.
 */
export function crossCheck(input: CrossCheckInput): Finding[] {
  const publicIndex = certificateIndex([...input.publicRootPems]);

  // Deduplicated across stores, so macOS's two keychains holding the same root
  // count it once, and sorted, so the report is identical for identical input.
  const anchorsPerStore = new Map<TrustStoreOutcome, StoreAnchors>();
  const all = new Map<string, Anchor>();
  for (const store of input.osStores) {
    if (store.failure !== null) continue;
    const parsed = anchorsOf(store.pems);
    anchorsPerStore.set(store, parsed);
    for (const [key, anchor] of parsed.anchors) {
      if (!all.has(key)) all.set(key, anchor);
    }
  }

  // Named factually and never "corporate": a public root merely newer than the
  // runtime's bundled snapshot lands in exactly this set (ADR-0031).
  const locallyAdded = [...all.values()]
    .filter((anchor) => !publicIndex.hasCertificate(anchor.der))
    .sort(byCanonicalSubject);

  const coverage = osCoverage(input.osStores, anchorsPerStore);
  const findings = osFindings(input, anchorsPerStore, new Set(locallyAdded.map((anchor) => derKey(anchor.der))));

  for (const runtime of input.runtimes) {
    const outcomes = input.runtimeStores.filter((outcome) => outcome.runtime === runtime);
    findings.push(...runtimeFindings(runtime, outcomes, locallyAdded, input, coverage));
  }

  if (coverage.level === 'none') {
    findings.push({
      id: 'truststore.crosscheck.indeterminate',
      probe: PROBE,
      severity: 'unknown',
      title: 'No OS trust store could be read, so no runtime could be cross-checked',
      evidence: [{ label: 'stores attempted', value: String(input.osStores.length), kind: 'number' }],
      remediation:
        'No OS trust store could be read, so portcall cannot tell which of this machine’s roots ' +
        'your runtimes are missing. The findings above say why the read failed; fix that and ' +
        're-run.',
    });
  }

  return findings;
}
