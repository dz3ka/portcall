// A hostile PAC script that answers normally and then never lets go of the
// thread: `vm`'s `timeout` bounds synchronous execution, so it is already
// over by the time this microtask chain starts running, and nothing inside
// the evaluator can interrupt it afterwards.
function FindProxyForURL(url, host) {
  function spin() {
    Promise.resolve().then(spin);
  }
  spin();
  return 'PROXY hostile.corp.internal:8080';
}
