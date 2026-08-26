// GADGET: walking the global object's prototype chain, five ways.
//
// The generalisation of `this.constructor.constructor`: any route from the
// sandbox global to *some* realm's `Object.prototype` gives that realm's
// `Function`, and if it is the host's realm the per-context
// `codeGeneration: { strings: false }` flag no longer applies. `globalThis`,
// `__proto__`, `Object.getPrototypeOf`, a captured `Object` and an object
// literal are all the same walk wearing different syntax, so a fix that
// blocked only the spelling in `hostile-escape-this-constructor.js` would be
// no fix at all.
//
// IF ANY OF THESE SUCCEEDS it returns
// `PROXY <process.env.PORTCALL_PAC_ESCAPE_CANARY>:8080`.
//
// Sealed by ADR-0011 item 5: under `DONT_CONTEXTIFY` every one of these
// walks terminates inside the sandbox realm.
function FindProxyForURL(url, host) {
  var walks = [
    function () { return globalThis.constructor.constructor; },
    function () { return globalThis.__proto__.constructor.constructor; },
    function () { return Object.getPrototypeOf(globalThis).constructor.constructor; },
    function () { return ({}).__proto__.constructor.constructor; },
    function () { return Object.getPrototypeOf(Object.getPrototypeOf({ a: 1 })).constructor; },
  ];

  for (var i = 0; i < walks.length; i += 1) {
    try {
      var proc = walks[i]()("return process")();
      return "PROXY " + proc.env.PORTCALL_PAC_ESCAPE_CANARY + ":8080";
    } catch (e) {
      // Next spelling.
    }
  }
  return "BLOCKED global-proto";
}
