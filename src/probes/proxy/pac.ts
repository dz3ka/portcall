import vm from 'node:vm';
import { PAC_BOOTSTRAP_SOURCE } from './pac-bootstrap.ts';

/**
 * PAC (Proxy Auto-Config) script evaluation (M2).
 *
 * Pure at the module boundary — no sockets, no filesystem — but not pure in
 * the usual sense inside: `ctx.scriptText` is untrusted JavaScript, and this
 * file's whole job is running it safely via `node:vm`. See ADR (M2, proxy
 * probe) for why `node:vm` and not an npm PAC-JS parser or a hand-rolled
 * JS-subset interpreter: no maintained small PAC-JS package exists that
 * would not itself be a security-review line item for executing untrusted
 * script, and hand-rolling a parser is more code in exactly the place
 * correctness matters least. Zero new dependency.
 *
 * Every hardening measure below defends a distinct attack. None may be
 * dropped without weakening a real property this tool promises (SPEC.md
 * §4): no network calls outside the profile allowlist, no writes, no
 * credential access.
 */

/**
 * PAC files are a handful of KB in the wild (WPAD payloads, corporate proxy
 * scripts). 1MB is two to three orders of magnitude of headroom over any
 * legitimate script and still compiles in well under a millisecond, so it
 * costs nothing to reject anything past it before `node:vm` ever sees it.
 */
export const MAX_SCRIPT_BYTES = 1_000_000;

export interface PacContext {
  /** Never emitted as evidence — see the module comment and `evaluatePac`. */
  scriptText: string;
  /**
   * The one host this evaluation is allowed to "resolve". The impure shell
   * resolves the endpoint host once via the system resolver *before* calling
   * `evaluatePac` and hands the answer in here — the sandbox never performs
   * its own DNS resolution. See the ADR-0012 rule on `dnsResolve` in
   * `pac-bootstrap.ts`.
   */
  resolvedTarget: { host: string; addresses: readonly string[] } | null;
  /** Caller-computed (`os.networkInterfaces()`); backs `myIpAddress()`. */
  myAddress: string;
  /** Injected for determinism; reserved for date/time PAC helpers this WP does not implement (see report). */
  now: Date;
}

export type PacVerdict =
  | { kind: 'proxy'; host: string; port: number }
  | { kind: 'direct' }
  | { kind: 'unresolved' }
  | { kind: 'error' };

/**
 * The only values that cross into the sandbox, and they are all strings.
 *
 * `targetJson` rather than the object: `JSON.parse` happens inside the
 * sandbox realm, so the helpers close over an object this realm never
 * touched. `'null'` is the no-pre-resolved-target case.
 */
interface PacHandoff {
  url: string;
  host: string;
  targetJson: string;
  myAddress: string;
}

/**
 * Write the four handoff strings onto the context's global.
 *
 * Primitives only, deliberately: a string copies into the sandbox realm as a
 * value, while any object or function would stay a handle back into *this*
 * realm and hand the script a prototype chain to walk. The bootstrap script
 * reads these four and `delete`s them before the untrusted script runs.
 */
function seedHandoff(globalObject: object, handoff: PacHandoff): void {
  const slots = globalObject as Record<string, string>;
  slots['__pacUrl'] = handoff.url;
  slots['__pacHost'] = handoff.host;
  slots['__pacTargetJson'] = handoff.targetJson;
  slots['__pacMyAddress'] = handoff.myAddress;
}

/**
 * `import("node:fs")` is syntax, not a global, so no sandbox shape can
 * remove it - the only lever is the host's dynamic-import hook. Refusing
 * here means a PAC script that tries it gets a rejected promise and loads
 * nothing.
 *
 * Node only consults this callback when the process runs with
 * `--experimental-vm-modules`; without that flag it throws
 * `ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING_FLAG` from inside the import
 * promise instead. Either way no module is ever loaded into the sandbox -
 * the difference is only in whose error text lands on the rejection, and an
 * unhandled one takes the thread down, which is precisely the failure mode
 * ADR-0017's Worker exists to convert into an `error` verdict.
 */
function refuseDynamicImport(): never {
  throw new Error('dynamic import is disabled inside the PAC sandbox');
}

/**
 * Parse whatever `FindProxyForURL` returned into a closed verdict.
 *
 * Only the first entry of a fallback chain (`"PROXY a:1; PROXY b:2; DIRECT"`)
 * is read — the script's own ordered preference. Anything that is not a
 * string, is empty, or does not parse as `DIRECT`/`PROXY host:port` (the
 * `HTTP` alias some scripts use is accepted as the same shape) is
 * `unresolved`: the script ran to completion and gave an answer this tool
 * cannot act on, which is a different, calmer fact than a crash.
 */
function parseVerdict(raw: unknown): PacVerdict {
  if (typeof raw !== 'string') return { kind: 'unresolved' };

  const first = (raw.split(';')[0] ?? '').trim();
  if (first === '') return { kind: 'unresolved' };
  if (/^DIRECT$/i.test(first)) return { kind: 'direct' };

  const match = /^(?:PROXY|HTTP)\s+([^\s:]+):(\d+)$/i.exec(first);
  if (match !== null) {
    const hostText = match[1];
    const portText = match[2];
    if (hostText !== undefined && portText !== undefined) {
      const port = Number.parseInt(portText, 10);
      if (Number.isInteger(port) && port > 0 && port <= 65535) return { kind: 'proxy', host: hostText, port };
    }
  }

  return { kind: 'unresolved' };
}

/**
 * Evaluate a PAC script against one `(url, host)` request.
 *
 * `ctx.scriptText` never appears in the return value, and no caught error's
 * `message` is read anywhere in this function — a PAC script routinely
 * embeds internal hostnames in `dnsDomainIs(...)` calls, and `PacVerdict` is
 * a closed union with no room for free text, so there is structurally
 * nowhere for script content to leak into a `Finding`'s evidence.
 *
 * Hardening, one line per item. Item 5 is the load-bearing one and the
 * reason this function no longer builds a sandbox object at all: a `vm`
 * context is a weaker boundary than it looks, and both of the escapes below
 * were demonstrated against the previous shape of this file.
 * 1. fresh context every call — no state reuse across hosts or runs.
 * 2. `codeGeneration: { strings: false, wasm: false }` — blocks `eval`,
 *    `Function` and `WebAssembly` *for code compiled in this context*. It is
 *    a per-context flag, which is exactly why it is not sufficient on its
 *    own: `Function` reached through some host realm's object answers to
 *    that realm's flag, not this one's.
 * 3. `script.runInContext(context, { timeout: timeoutMs })` — kills
 *    `while(true){}`; the script body and the `FindProxyForURL` call run
 *    inside the *same* timed script, so a loop hidden inside the function
 *    and only reached at call time is bounded too. It bounds synchronous
 *    execution only; microtask starvation is ADR-0017's Worker's job.
 * 4. size cap pre-compilation — `MAX_SCRIPT_BYTES`, checked before `node:vm`
 *    sees the text at all.
 * 5. `vm.constants.DONT_CONTEXTIFY` — the context global is an ordinary
 *    global of a fresh realm rather than a host object behind an
 *    interceptor, and *nothing* from this realm is placed on it. With a
 *    contextified host sandbox, `this.constructor.constructor("return
 *    process")()` walked the sandbox object's prototype chain into the host
 *    realm's `Object.prototype` and returned the live `process` — with the
 *    helpers deleted entirely, measured. Uncontextified, the same gadget
 *    reaches this realm's own `Function` and stops at `EvalError: Code
 *    generation from strings disallowed`. There is no `require`, `process`,
 *    `global` or `Buffer`: a fresh realm has only the JS intrinsics.
 * 6. helpers as in-context source (`pac-bootstrap.ts`), never host function
 *    objects — `dnsResolve.constructor("return process")()` was a working
 *    escape for exactly as long as `dnsResolve` was a function of this
 *    realm, `Object.freeze` notwithstanding.
 * 7. primitives only, both directions — four strings in via `seedHandoff`,
 *    which the bootstrap deletes; the verdict out as the run's completion
 *    value, `typeof`-gated in the sandbox and again in `parseVerdict`. No
 *    read-back of a sandbox property, so no script-created object is ever
 *    touched by this realm.
 * 8. `refuseDynamicImport` — `import()` cannot be removed by shaping the
 *    global, so the host hook refuses it.
 * 9. `dnsResolve`/`isInNet`/`isResolvable` see only `ctx.resolvedTarget`, and
 *    `myIpAddress()` only `ctx.myAddress` — no lookup and no interface
 *    enumeration can happen inside the sandbox (ADR-0012).
 * 10. the async continuation gap (gadget 7: a dangling `import()` rejection
 *     handler that only runs once this synchronous call returns control to
 *     the event loop) is not closed here — this function stays synchronous
 *     end to end. It is closed one level up, at the worker boundary
 *     (`pac-worker.ts`'s immediate `process.exit(0)` after reply, ADR-0019),
 *     which prevents that event-loop turn from ever happening.
 *
 * What this does *not* claim: `node:vm` is not a security boundary Node
 * itself guarantees, and a V8 bug or a future Node change can move the line
 * again. That is why the Worker (ADR-0017) and the profile allowlist stay in
 * front of it — this function is one layer, not the only one.
 */
export function evaluatePac(url: string, host: string, ctx: PacContext, timeoutMs: number): PacVerdict {
  if (ctx.scriptText.length > MAX_SCRIPT_BYTES) return { kind: 'error' };

  let context: vm.Context;
  try {
    context = vm.createContext(vm.constants.DONT_CONTEXTIFY, { codeGeneration: { strings: false, wasm: false } });
    seedHandoff(context, {
      url,
      host,
      targetJson: JSON.stringify(ctx.resolvedTarget),
      myAddress: ctx.myAddress,
    });
    const bootstrap = new vm.Script(PAC_BOOTSTRAP_SOURCE, {
      filename: 'pac-bootstrap.js',
      importModuleDynamically: refuseDynamicImport,
    });
    bootstrap.runInContext(context, { timeout: timeoutMs });
  } catch {
    // Nothing here is untrusted, so this only fires if the runtime refuses
    // the context or the bootstrap itself is broken. `error` all the same.
    return { kind: 'error' };
  }

  // One combined script: the script's own top-level code (which must define
  // `FindProxyForURL`) followed by the call that invokes it. Combining them
  // means the `timeout` below bounds *both* phases as a single synchronous
  // execution, and the call's return value is the script's completion value,
  // so the verdict comes back as a return rather than as a property this
  // realm would have to read off the sandbox.
  const combinedSource = `${ctx.scriptText}
;__pacRun();`;

  let raw: unknown;
  try {
    const script = new vm.Script(combinedSource, { filename: 'pac.js', importModuleDynamically: refuseDynamicImport });
    raw = script.runInContext(context, { timeout: timeoutMs });
  } catch {
    // Syntax error, thrown exception, undefined FindProxyForURL, or the
    // timeout above firing — all collapse to `error`. None of their messages
    // are read: see the module/function comment on why that matters here.
    return { kind: 'error' };
  }

  return parseVerdict(raw);
}
