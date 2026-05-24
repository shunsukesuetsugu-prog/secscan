// Borderline-clean counterpart to cwe78_cmd_injection.js.
// Uses execFile with an argv array — no shell interpolation.

const { execFile } = require('child_process');

function runUserCommandSafely(userInput) {
  // NOT a CWE-78: execFile with argv list, no shell.
  execFile('echo', [userInput], (err, stdout) => {
    if (err) throw err;
    return stdout;
  });
}

module.exports = { runUserCommandSafely };
