// The same denial of service written the other way round: `await` schedules
// the continuation as a microtask, so this recursion starves the event loop
// exactly like `hostile-microtask-loop.js` does, without a visible `.then`.
function FindProxyForURL(url, host) {
  async function spin() {
    await null;
    return spin();
  }
  spin();
  return 'DIRECT';
}
