// GADGET: intrinsics other than the global - a thrown error, a string, an
// array, a number, and the async/generator function constructors.
//
// The two confirmed escapes both went through the sandbox *global*. This one
// exists because the global is not the only object in the realm: every
// literal has a prototype, every prototype has a `.constructor`, and the
// function-family constructors (`AsyncFunction`, `GeneratorFunction`) are
// reachable without ever naming `Function`. If any intrinsic in the sandbox
// belonged to the host realm - because it was handed in, or because an error
// crossing the boundary was constructed on the host side - this returns
// `PROXY <process.env.PORTCALL_PAC_ESCAPE_CANARY>:8080`.
//
// Unlike the two `*-constructor` fixtures beside it this one is not a
// historical repro: it did not work against the old contextified shape
// either, because these intrinsics have always come from the vm realm. It is
// here as the regression that catches a *future* change that starts handing
// host objects in again - a host-realm error object caught by a PAC script
// would be the same escape in a new costume.
function FindProxyForURL(url, host) {
  var reached = [];

  try {
    null.thisAlwaysThrows();
  } catch (thrown) {
    reached.push(thrown.constructor.constructor);
    reached.push(Object.getPrototypeOf(thrown).constructor.constructor);
  }

  try {
    throw new Error("attacker-constructed");
  } catch (thrown) {
    reached.push(thrown.constructor.constructor);
  }

  reached.push("".constructor.constructor);
  reached.push([].constructor.constructor);
  reached.push((0).constructor.constructor);
  reached.push(Object.getPrototypeOf(function () {}).constructor);
  reached.push(Object.getPrototypeOf(async function () {}).constructor);
  reached.push(Object.getPrototypeOf(function* () {}).constructor);

  for (var i = 0; i < reached.length; i += 1) {
    try {
      var proc = reached[i]("return process")();
      return "PROXY " + proc.env.PORTCALL_PAC_ESCAPE_CANARY + ":8080";
    } catch (e) {
      // Next constructor.
    }
  }
  return "BLOCKED error-constructor";
}
