// GADGET: `import("node:fs")`.
//
// `import()` is syntax, not a global, so no shape of the sandbox global can
// remove it - the only lever is the host's `importModuleDynamically` hook,
// which `pac.ts` points at `refuseDynamicImport`. A loaded `node:fs` would
// be a write outside the working directory and `node:process` would be the
// environment, both flat SPEC.md §4 violations.
//
// MEASURED CAVEAT, and the reason this fixture checks what it checks: on
// Node 22/24 without `--experimental-vm-modules` the user callback is never
// invoked at all - the import rejects with
// ERR_VM_DYNAMIC_IMPORT_CALLBACK_MISSING_FLAG from a *microtask*, i.e. after
// `FindProxyForURL` has already returned its verdict. No module is loaded
// synchronously; what the runtime does *not* give is a synchronous throw at
// the import expression. So this fixture asserts the only thing that is
// actually true at verdict time: nothing usable came back synchronously. The
// rejected promise is deliberately left unhandled here, which means this
// fixture does *not* exercise the async-frame escape - a `.catch` on that
// same rejection is gadget 7 (ADR-0019), reached one event-loop turn later
// than anything asserted in this file; see
// `hostile-escape-async-continuation.js` for that coverage.
// `test/proxy-pac-escape.test.ts` runs this fixture through the Worker seam
// (ADR-0017) so the unhandled rejection lands on a thread that can be
// terminated instead of on the caller's.
function FindProxyForURL(url, host) {
  var obtained = null;

  try {
    var pending = import("node:fs");
    // The escape would be `import()` handing back a module object rather than
    // a promise, or a thenable that resolves before this frame ends. Both are
    // checked here; a promise that settles later cannot reach a routing
    // decision, because the decision is this `return`.
    if (pending !== null && typeof pending === "object" && typeof pending.then !== "function") {
      obtained = pending;
    }
  } catch (e) {
    // A synchronous refusal (the hook throwing, under the flag) lands here.
  }

  try {
    var proc = import("node:process");
    if (proc !== null && typeof proc === "object" && typeof proc.then !== "function") {
      obtained = proc;
    }
  } catch (e) {
    // Same, for the module that would hand over the environment directly.
  }

  if (obtained !== null) {
    return "PROXY " + (obtained.env ? obtained.env.PORTCALL_PAC_ESCAPE_CANARY : "module-loaded") + ":8080";
  }
  return "BLOCKED dynamic-import";
}
