// CWE-95 / CWE-502 fixture: eval of untrusted input.
// Expected to be detected by p/javascript rules.

function runUserExpression(userInput) {
  // CWE-95: dynamic code execution from untrusted input.
  return eval(userInput);
}

module.exports = { runUserExpression };
