const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');

function imageSources() {
  const dockerfile = fs.readFileSync('Dockerfile', 'utf8');
  return new Set(dockerfile.split('\n').filter((line) => line.startsWith('COPY '))
    .flatMap((line) => line.slice(5).trim().split(/\s+/).slice(0, -1)));
}

function shellAssets() {
  const html = fs.readFileSync('index.html', 'utf8');
  const references = [...html.matchAll(/\b(?:src|href)="([^"]+)"/g)].map((match) => match[1]);
  const worker = fs.readFileSync('sw.js', 'utf8');
  const shell = worker.match(/const SHELL = (\[[^;]+?\])\.map\(/s);
  assert.ok(shell, 'service worker must declare its shell assets');
  return [...references, ...JSON.parse(shell[1])]
    .filter((value) => !/^(?:https?:|#)/.test(value))
    .map((value) => value.split('?')[0].replace(/^\/sovagrid\/monitoring\//, '').replace(/^\//, ''))
    .filter(Boolean);
}

test('every HTML and offline-shell asset is packaged in the Web image', () => {
  const sources = imageSources();
  for (const asset of shellAssets()) {
    assert.ok(fs.existsSync(asset), `referenced asset is absent from source: ${asset}`);
    assert.ok([...sources].some((source) => asset === source || asset.startsWith(`${source}/`)),
      `referenced asset is absent from Web image: ${asset}`);
  }
});
