// GADGET: `this.constructor.constructor`.
//
// The deeper of the two confirmed escapes, and the one that still worked
// with every helper deleted. `vm.createContext(hostObject)` contextifies a
// *host* object: the sandbox global's own prototype chain therefore reached
// the host realm's `Object.prototype`, so `this.constructor` was the host
// `Object` and `this.constructor.constructor` the host `Function`. Nothing
// about the shape of the sandbox contents could close that - the container
// itself was the leak.
//
// Both `this` bindings are tried: the one inside the call (a sloppy-mode
// function called with no receiver gets the realm's global) and the one
// captured at the script's top level.
//
// IF THIS SUCCEEDS it returns `PROXY <process.env.PORTCALL_PAC_ESCAPE_CANARY>:8080` -
// host-realm code execution from a routing file.
//
// Sealed by ADR-0011 item 5: `vm.constants.DONT_CONTEXTIFY` makes the global
// an ordinary global of a fresh realm, so the same walk lands on the
// sandbox's own `Function` and stops at `EvalError: Code generation from
// strings disallowed`.
var capturedTopLevelThis = this;

function FindProxyForURL(url, host) {
  var receivers = [this, capturedTopLevelThis];
  for (var i = 0; i < receivers.length; i += 1) {
    try {
      var proc = receivers[i].constructor.constructor("return process")();
      return "PROXY " + proc.env.PORTCALL_PAC_ESCAPE_CANARY + ":8080";
    } catch (e) {
      // Try the next receiver; a single dead binding proves nothing.
    }
  }
  return "BLOCKED this-constructor";
}
