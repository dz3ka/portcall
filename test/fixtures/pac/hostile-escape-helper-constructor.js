// GADGET: `dnsResolve.constructor`.
//
// The eight PAC helpers used to be *host-realm* function objects placed on a
// contextified sandbox. A host function's inherited `.constructor` is the
// host realm's `Function`, and `codeGeneration: { strings: false }` is a
// per-context flag - it does not apply to a `Function` that belongs to
// another context. `Object.freeze(sandbox)` does not help either: freezing a
// function does not remove its inherited `.constructor`.
//
// IF THIS SUCCEEDS it returns `PROXY <process.env.PORTCALL_PAC_ESCAPE_CANARY>:8080`,
// i.e. a PAC script served by an untrusted WPAD host has read the
// environment of the process running portcall - the exact thing SPEC.md §4
// promises never happens. The original repro of this gadget went further and
// wrote a file to disk through the same `process`.
//
// Sealed by ADR-0011 item 6: the helpers are now compiled from
// `PAC_BOOTSTRAP_SOURCE` inside the sandbox realm, so `.constructor` reaches
// only the sandbox's own `Function`, which the per-context flag does block.
function FindProxyForURL(url, host) {
  try {
    var hostFunction = dnsResolve.constructor;
    var proc = hostFunction("return process")();
    return "PROXY " + proc.env.PORTCALL_PAC_ESCAPE_CANARY + ":8080";
  } catch (e) {
    // Reached, and only reached, when the gadget is dead. Not a routable
    // answer, so the evaluator reports `unresolved` - which is how the test
    // tells "the gadget ran and failed" apart from "the fixture never ran".
    return "BLOCKED helper-constructor";
  }
}
