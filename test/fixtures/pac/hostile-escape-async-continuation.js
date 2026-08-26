// GADGET 7: the async continuation gap.
//
// `FindProxyForURL` returns synchronously, same as any well-behaved script -
// the routing decision this file returns is not the attack. The attack is a
// `.catch` handler attached to a dangling `import("node:fs")`, which only
// runs once this synchronous call returns control to the event loop and the
// microtask queue drains. `refuseDynamicImport` (pac.ts) still refuses the
// import, but the rejection error object `e` is a normal object of *this*
// realm - `codeGeneration: { strings: false }` is a per-context flag, so
// `e.constructor.constructor("return process")()` reaches this realm's own
// `Function` and returns the live `process`, exactly like gadget 2 but
// reached one event-loop turn later than any test in this file previously
// exercised.
//
// This fixture is deliberately absent from IN_THREAD_FIXTURES and from the
// dynamic-import describe block: it only proves anything through the
// production `createPacSandbox()` seam (ADR-0017's Worker), because the fix
// under test (ADR-0019) is `pac-worker.ts` self-exiting before that turn can
// happen - a bare `evaluatePac()` call has no such exit and was never this
// fix's guarantee (see the architect's stated non-goal, session I).
function FindProxyForURL(url, host) {
  var pending = import("node:fs");
  pending.catch(function (e) {
    try {
      var proc = e.constructor.constructor("return process")();
      var os = proc.getBuiltinModule("node:os");
      var fs = proc.getBuiltinModule("node:fs");
      var path = proc.getBuiltinModule("node:path");
      var canaryPath = path.join(os.tmpdir(), "portcall-pac-escape-gadget7.canary");
      fs.writeFileSync(canaryPath, proc.env.PORTCALL_PAC_ESCAPE_CANARY || "no-canary-env");
    } catch (writeErr) {
      // If confinement still holds one turn later (the fix), `proc` is never
      // reached and this branch never runs - there is nothing to report from
      // inside a hostile script that failed, by design.
    }
  });

  return "DIRECT";
}
