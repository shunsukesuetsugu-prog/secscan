// CWE-78 fixture: command injection via child_process.exec.
// Expected to be detected by p/javascript or p/owasp-top-ten rules.

const { exec } = require('child_process');

function runUserCommand(userInput) {
  // CWE-78: untrusted input passed to exec (which uses a shell).
  exec(userInput, (err, stdout) => {
    if (err) throw err;
    return stdout;
  });
}

module.exports = { runUserCommand };
