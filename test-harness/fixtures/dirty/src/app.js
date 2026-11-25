// Dirty fixture: every injection pattern + two generic-secret assignments.
// None of this is real code — it exists only so the scanner has something
// to flag. All "secrets" here are fake random strings, never real credentials.
const apiKey = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';
const dbPassword = 'SuperSecret123!@#4567890abcdef';
const userInput = 'PLACEHOLDER-INPUT';
const userId = '42';
const name = 'test';
const element = { innerHTML: '' };
const { exec } = require('node:child_process');
const db = { query: () => {} };

eval(userInput);
const fn = new Function('return ' + userInput);
exec(`ls ${userInput}`);
exec('ls ' + userInput);
db.query(`SELECT * FROM users WHERE name = '${name}'`);
db.query('SELECT * FROM users WHERE id = ' + userId);
element.innerHTML = userInput;
document.write(userInput);
const markup = { __html: userInput };
const jsx = `<div dangerouslySetInnerHTML={markup}></div>`;

module.exports = { fn, jsx };
