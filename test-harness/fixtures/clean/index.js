// Clean fixture: ordinary code with no secrets, no vulnerable deps,
// no injection patterns. If the scanner flags anything here, the scanner
// is wrong — not the fixture.
function add(a, b) {
  return a + b;
}

const greeting = 'hello, world';

module.exports = { add, greeting };
