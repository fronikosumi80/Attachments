const test = require('node:test');
const assert = require('node:assert/strict');
const packageJson = require('../package.json');

test('installer metadata is release-ready', () => {
  assert.match(packageJson.version, /^\d+\.\d+\.\d+$/);
  assert.equal(packageJson.build.artifactName, 'CyberFronSecurity-Setup.exe');
  assert.equal(packageJson.build.nsis.createStartMenuShortcut, true);
});
