import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {test} from 'node:test';

const uploader = fileURLToPath(new URL('./upload-web-release.mjs', import.meta.url));
const tag = '20261004-abcd';
const target = {bucket: 'web-assets', prefix: '/libraries/blahdiem/', region: 'eu-west-1',
  accessKeyId: 'fixture-access', secretAccessKey: 'fixture/secret+$key'};
const assets = ['diem.js', 'diem.wasm', 'diem.d.ts', 'bridge-js.d.ts', 'package.json', 'manifest.json',
  'LICENSE', 'THIRD_PARTY_LICENSES', 'README.md', 'SHA256SUMS'];

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'blahdiem-upload-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  const artifact = join(root, 'artifact');
  mkdirSync(join(artifact, 'dist'), {recursive: true});
  for(const name of assets) writeFileSync(join(artifact, 'dist', name), `fixture ${name}\n`);
  for(const name of ['diem.js.gz', 'diem.js.br', 'diem.wasm.gz', 'diem.wasm.br']) {
    writeFileSync(join(artifact, 'dist', name), 'compressed variant must stay on GitHub');
  }
  writeFileSync(join(artifact, 'blahdiem-web.tar.gz'), 'archive must stay on GitHub');
  const calls = join(root, 'calls.jsonl');
  writeFileSync(join(root, 'aws'), `#!/usr/bin/env node
const {appendFileSync, readFileSync} = require('node:fs');
const args = process.argv.slice(2);
appendFileSync(process.env.UPLOAD_TEST_CALLS, JSON.stringify({args,
  body: readFileSync(args[2], 'utf8'),
  env: Object.fromEntries(Object.entries(process.env).filter(([key]) => key.startsWith('AWS_') || key === 'WEB_RELEASE_S3_TARGETS'))}) + '\\n');
if(process.env.UPLOAD_TEST_FAIL) {
  console.error(process.env.AWS_SECRET_ACCESS_KEY);
  process.exit(1);
}
`, {mode: 0o755});
  return {
    artifact,
    run(config, releaseTag = tag, extraEnv = {}) {
      return spawnSync(process.execPath, [uploader, artifact, releaseTag], {encoding: 'utf8',
        env: {...process.env, PATH: `${root}:${process.env.PATH}`,
          WEB_RELEASE_S3_TARGETS: typeof config === 'string' ? config : JSON.stringify(config),
          UPLOAD_TEST_CALLS: calls, ...extraEnv}});
    },
    calls() {
      try { return readFileSync(calls, 'utf8').trim().split('\n').map(line => JSON.parse(line)); }
      catch(error) { if(error.code === 'ENOENT') return []; throw error; }
    },
  };
}

test('uploads only uncompressed web assets to each prefix/tag with isolated credentials and serving metadata', t => {
  const f = fixture(t);
  const second = {bucket: 'mirror-assets', prefix: 'web library/v2', endpointUrl: 'https://objects.example.test',
    accessKeyId: 'mirror-access', secretAccessKey: 'mirror-secret', sessionToken: 'mirror-session'};
  const result = f.run([target, second], tag, {AWS_PROFILE: 'unrelated-profile',
    AWS_ENDPOINT_URL: 'https://wrong.example.test', AWS_SESSION_TOKEN: 'unrelated-session'});
  assert.equal(result.status, 0, result.stderr);
  const calls = f.calls();
  assert.equal(calls.length, assets.length * 2);
  for(const [index, settings] of [target, second].entries()) {
    const batch = calls.slice(index * assets.length, (index + 1) * assets.length);
    const prefix = index === 0 ? 'libraries/blahdiem' : 'web library/v2';
    assert.deepEqual(new Set(batch.map(call => call.args[3])),
      new Set(assets.map(name => `s3://${settings.bucket}/${prefix}/${tag}/${name}`)));
    for(const {args, env, body} of batch) {
      const name = args[3].split('/').at(-1);
      assert.deepEqual(args.slice(0, 2), ['s3', 'cp']);
      assert.equal(body, `fixture ${name}\n`);
      assert.equal(args[args.indexOf('--region') + 1], settings.region ?? 'us-east-1');
      assert.equal(env.AWS_ACCESS_KEY_ID, settings.accessKeyId);
      assert.equal(env.AWS_SECRET_ACCESS_KEY, settings.secretAccessKey);
      assert.equal(env.AWS_SESSION_TOKEN, settings.sessionToken ?? '');
      assert.equal(env.AWS_CONFIG_FILE, '/dev/null');
      assert.equal(env.AWS_SHARED_CREDENTIALS_FILE, '/dev/null');
      assert.equal(env.AWS_PROFILE, undefined);
      assert.equal(env.AWS_ENDPOINT_URL, undefined);
      assert.equal(env.WEB_RELEASE_S3_TARGETS, undefined);
      assert(!args.includes(settings.secretAccessKey));
      if(settings.endpointUrl) assert.equal(args[args.indexOf('--endpoint-url') + 1], settings.endpointUrl);
      else assert(!args.includes('--endpoint-url'));
      const type = name.startsWith('diem.js') ? 'text/javascript' : name.startsWith('diem.wasm') ? 'application/wasm' : name.endsWith('.json') ? 'application/json' : 'text/plain';
      assert.equal(args[args.indexOf('--content-type') + 1], type);
      assert(!args.includes('--content-encoding'));
    }
  }
  for(const settings of [target, second]) {
    for(const value of Object.values(settings)) assert(!(result.stdout + result.stderr).includes(value));
  }
});

test('a single bucket can serve from its root, without a release archive', t => {
  const f = fixture(t);
  rmSync(join(f.artifact, 'blahdiem-web.tar.gz'));
  const result = f.run([{...target, prefix: ''}]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(f.calls().length, assets.length);
  assert(f.calls().every(call => call.args[3].startsWith(`s3://web-assets/${tag}/`)));
});

test('unset and empty targets skip uploads without requiring an artifact or AWS CLI', t => {
  const f = fixture(t);
  rmSync(f.artifact, {recursive: true});
  for(const config of ['', '  ', []]) {
    const result = f.run(config);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /skipping S3 uploads/);
  }
  assert.deepEqual(f.calls(), []);
});

test('invalid configuration is rejected before any upload without printing secret values', t => {
  const f = fixture(t);
  for(const config of ['{"secretAccessKey":"do-not-print",', {}, null, [null],
    [target, {...target, secretAccessKey: ''}], [{...target, bucket: 'bucket/path'}],
    [{...target, prefix: '../escape'}], [{...target, prefix: 'path/./asset'}],
    [{...target, prefix: 'path//asset'}], [{...target, prefix: 10}],
    [{...target, region: ''}], [{...target, endpointUrl: 'https://user:password@example.test'}],
    [{...target, endpointUrl: 'not a URL'}], [{...target, region: 'us-east-1\n'}],
    [{...target, secretAccessKey: 'do-not-print\n'}], [{...target, typo: 'do-not-print'}]]) {
    const result = f.run(config);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /WEB_RELEASE_S3_TARGETS/);
    assert(!(result.stdout + result.stderr).includes('do-not-print'));
    assert(!(result.stdout + result.stderr).includes(target.secretAccessKey));
  }
  assert.deepEqual(f.calls(), []);
});

test('invalid tags and missing, empty or non-file assets fail before uploading', t => {
  const f = fixture(t);
  assert.equal(f.run([target], '../another-release').status, 1);
  writeFileSync(join(f.artifact, 'dist', 'diem.js'), '');
  assert.equal(f.run([target]).status, 1);
  writeFileSync(join(f.artifact, 'dist', 'diem.js'), 'restored');
  mkdirSync(join(f.artifact, 'dist', 'unexpected-directory'));
  assert.equal(f.run([target]).status, 1);
  rmSync(join(f.artifact, 'dist'), {recursive: true});
  mkdirSync(join(f.artifact, 'dist'));
  assert.equal(f.run([target]).status, 1);
  rmSync(join(f.artifact, 'dist'), {recursive: true});
  assert.equal(f.run([target]).status, 1);
  assert.deepEqual(f.calls(), []);
});

test('a failed upload fails the release job and does not expose raw CLI errors', t => {
  const f = fixture(t);
  const result = f.run([target], tag, {UPLOAD_TEST_FAIL: '1'});
  assert.equal(result.status, 1);
  assert.match(result.stderr, /S3 target 1: upload failed/);
  assert(!result.stderr.includes(target.secretAccessKey));
  assert.equal(f.calls().length, 1);
});
