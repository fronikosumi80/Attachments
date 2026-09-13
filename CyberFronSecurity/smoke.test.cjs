const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const packageJson = require('./package.json');

test('installer metadata is release-ready', () => {
  assert.match(packageJson.version, /^\d+\.\d+\.\d+$/);
  assert.equal(packageJson.build.artifactName, 'CyberFronSecurity-Setup.exe');
  assert.equal(packageJson.build.nsis.createStartMenuShortcut, true);
});

test('hosted download points to the published GitHub release asset', () => {
  const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');
  const script = fs.readFileSync(path.join(__dirname, 'index.js'), 'utf8');
  const releaseUrl = 'https://github.com/fronikosumi80/Attachments/releases/latest/download/CyberFronSecurity-Setup.exe';
  assert.equal((html.match(new RegExp(releaseUrl, 'g')) || []).length, 2);
  assert.match(script, new RegExp(releaseUrl.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\$&')));
  assert.doesNotMatch(html, /href="\.\/dist\/CyberFronSecurity-Setup\.exe"/);
});
