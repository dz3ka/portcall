// GADGET: return something that is not a string, and shadow the one function
// that is supposed to notice.
//
// The verdict leaves the sandbox as the run's completion value, and two
// `typeof === "string"` gates stand between a PAC script and the host realm:
// `__pacRun` in `PAC_BOOTSTRAP_SOURCE` and `parseVerdict` in `pac.ts`. This
// fixture removes the first one - `__pacRun` is an ordinary global that the
// untrusted script runs after, so it can simply be reassigned - and hands the
// host an object whose `toString` / `valueOf` / `Symbol.toPrimitive` all want
// to be called.
//
// IF THE HOST COERCES IT (`String(raw)`, `` `${raw}` ``, a template in a log
// line, a `.trim()` on an unchecked value) the coercion runs attacker code on
// the host's own stack, and the returned text - `PROXY <...>:8080` - becomes
// the proxy this tool then reports and connects through. That is the whole
// prize: the escape is not "read the environment" but "choose portcall's
// proxy from inside a routing file", and the canary is carried along to prove
// which side of the boundary the coercion happened on.
//
// Sealed by the second gate: `parseVerdict` rejects any non-string before
// anything touches it, so no property of a script-created object is ever read
// by this realm.
function probeHostRealm() {
  try {
    var proc = probeHostRealm.constructor("return process")();
    return proc.env.PORTCALL_PAC_ESCAPE_CANARY;
  } catch (e) {
    // Coerced, but still inside the sandbox realm: the routing lie lands even
    // though the environment read did not.
    return "coerced-in-sandbox";
  }
}

function leakyVerdict() {
  var answer = {
    toString: function () { return "PROXY " + probeHostRealm() + ":8080"; },
    valueOf: function () { return "PROXY " + probeHostRealm() + ":8080"; },
  };
  answer[Symbol.toPrimitive] = function () { return "PROXY " + probeHostRealm() + ":8080"; };
  return answer;
}

function FindProxyForURL(url, host) {
  return leakyVerdict();
}

// Shadow the bootstrap's gate: whatever `FindProxyForURL` returns now reaches
// the host uninspected by the sandbox side. The request url/host are not
// re-read from `__pacUrl`/`__pacHost` here - those slots are deleted before
// this script runs, which is its own test - and this gadget does not need
// them.
__pacRun = function () {
  return FindProxyForURL("https://api.example.com/", "api.example.com");
};
