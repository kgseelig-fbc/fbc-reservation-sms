const readline = require("readline");

function prompt(question, { mask = false } = {}) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    if (mask) {
      // Suppress echo for passwords.
      const stdin = process.stdin;
      const originalWrite = rl._writeToOutput;
      rl._writeToOutput = function (str) {
        if (str.includes(question)) originalWrite.call(rl, str);
        else originalWrite.call(rl, "*".repeat(Math.max(0, str.length - 1)));
      };
      rl.question(question, (answer) => {
        rl._writeToOutput = originalWrite;
        process.stdout.write("\n");
        rl.close();
        resolve(answer);
      });
    } else {
      rl.question(question, (answer) => { rl.close(); resolve(answer.trim()); });
    }
  });
}

async function required(label, opts) {
  while (true) {
    const v = await prompt(label, opts);
    if (v && v.trim()) return v.trim();
    console.log("  (required)");
  }
}

module.exports = { prompt, required };
