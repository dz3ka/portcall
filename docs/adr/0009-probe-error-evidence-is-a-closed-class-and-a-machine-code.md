# ADR-0009: Probe errors carry a closed class and a code, never the message

- **Status:** Accepted
- **Date:** 2026-08-25
- **Deciders:** Bogdan Dzekic

## Context

`runProbe`'s catch in `src/engine/index.ts:118` is the one place in the tree
where an arbitrary thrown `Error` - ours or Node's - becomes report content: a
probe that dies does not fail the run, so its throw becomes a `Finding` that
crosses the redaction boundary. M1 made it reachable: `PROBES` was `[]` until
the `dns` and `egress` probes registered.

The hazard is `error.message`, the least bounded string in the tool. Node
writes remote input into it - `getaddrinfo ENOTFOUND internal.corp.example`,
`connect ECONNREFUSED 10.0.0.5:443`, `ENOENT ... open '/home/jdoe/...'` - as
does `NetworkPolicyError`, naming the host it refused. As `text` it reaches the
report unhashed: redaction is by declared kind (ADR-0005), `public`, `text` and
`number` pass verbatim, `remediation` bypasses redaction entirely. ADR-0008's
rule - no probe emits a remote-derived string - must hold *above* the probes.

## Decision

The engine reads only typed fields off the thrown error, never `message` and
never `String(error)`. `src/engine/probe-error.ts`, its sole producer, reads
three things.

**Which class it is.** `ProbeErrorClass` is a closed three-member union -
`network-policy`, `aborted`, `unclassified` - reached by `instanceof` narrowing
plus a check of `error.name` for the `AbortError` and `TimeoutError`
`AbortSignal` rejects with. Three, because they are three sentences: we
refused, the clock ran out, we do not know. Emitted as `text`.

**A machine code, where the error carries one.** `extractCode`, the narrowing
`src/net/dns.ts` applies to every other code in the report, keeps only a
`MACHINE_CODE`-shaped errno; with none, the evidence reads `unavailable`, our
own literal, never anything the error supplied.

**The refused host, on a policy denial.** `NetworkPolicyError.host` is emitted
as `kind: 'hostname'`, so the boundary hashes it like any other internal name.

`remediation` is chosen by an exhaustive `switch` over the class and
interpolates only the probe name, a literal from the registry - it has to,
since remediation bypasses redaction. The operator who needs the real host runs
`--no-redact` (`src/cli/args.ts:74`, `src/cli/help.ts:20`), which already warns.

The producer is a module, not lines in the catch, because `run()` imports the
real `PROBES`: without it the error path is untestable without sockets.

## Alternatives considered

- **Reclassify the message as `kind: 'hostname'` in place.** A one-line fix,
  rejected on a present requirement rather than a speculative one:
  `redactEvidence` hashes the *whole* value, so a redacted report carries an
  opaque token where a readable errno belongs, while `--no-redact` returns the
  sentence, host included, in cleartext with no class or code replacing it.
- **Drop the evidence and emit the finding bare.** Rejected: a finding with
  nothing behind it is one the operator cannot diagnose or forward, which is
  close enough to not emitting it.

## Consequences

Every probe added in M2 to M4 funnels through this catch, so its error path is
bound by construction. `switch-exhaustiveness-check` plus the
`Record<ProbeErrorClass, true>` table in the six-row hostile-error case in
`test/guardrails/probe-evidence-kinds.test.ts` make the vocabulary
compile-checked and the leak testable.

The cost lands on novel failures: a genuinely new one reports `unclassified`
with a code and no prose, so adding a class is a deliberate edit rather than
free text - the trade ADR-0008 took for `EgressClass`.

Importing `extractCode` from `../net/dns.ts` makes `src/engine/probe-error.ts`
that function's third consumer, strengthening rather than creating the
shared-module follow-up ADR-0008 already records as an accepted wart.

Branching on `error.name` is runtime-influenced: a library can steer *which*
remediation is shown. Reviewed and accepted, because `name` is branched on and
never emitted - the worst case is a misworded remediation on an already
`unknown` finding, never a leak. This record extends ADR-0005 and ADR-0008, and
supersedes nothing.
