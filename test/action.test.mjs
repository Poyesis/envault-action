import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import action from '../dist/index.js';

const { run, DEFAULT_API_URL, maskCommands, fileCommandEntry, isReservedEnvName, ActionError } = action;
const ENTRY = fileURLToPath(new URL('../dist/index.js', import.meta.url));
const P = '11111111-2222-3333-4444-555555555555';

let server;
let base;
let requests = [];
let secrets = [];
let failResolve = 0;

before(async () => {
  server = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => (raw += c));
    req.on('end', () => {
      requests.push({ method: req.method, url: req.url, auth: req.headers.authorization, body: raw ? JSON.parse(raw) : undefined });
      const send = (status, body) => {
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(JSON.stringify(body));
      };
      const u = new URL(req.url, 'http://x');
      if (u.pathname === '/gh-oidc') {
        if (req.headers.authorization !== 'Bearer runner-req-token') return send(401, {});
        return send(200, { value: `gh-oidc-jwt-${u.searchParams.get('audience')}` });
      }
      if (u.pathname === '/v1/auth/oidc') return send(200, { token: 'envault-session-token', expiresIn: 600 });
      if (u.pathname === `/v1/projects/${P}/envs/staging/secrets:resolve`) {
        if (failResolve > 0) {
          failResolve--;
          return send(503, { message: 'unavailable' });
        }
        if (req.headers.authorization !== 'Bearer envault-session-token') return send(401, { message: 'unauthorized' });
        return send(200, { environment: 'staging', secrets });
      }
      send(404, { message: 'no route' });
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => new Promise((r) => server.close(r)));

function setup(inputs = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'envault-action-'));
  const env = {
    ACTIONS_ID_TOKEN_REQUEST_URL: `${base}/gh-oidc?api-version=2.0`,
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'runner-req-token',
    GITHUB_ENV: path.join(dir, 'env'),
    GITHUB_OUTPUT: path.join(dir, 'output'),
    'INPUT_API-URL': base,
    'INPUT_PROJECT-ID': P,
    INPUT_ENVIRONMENT: 'staging',
  };
  for (const [k, v] of Object.entries(inputs)) env[`INPUT_${k.toUpperCase()}`] = v;
  fs.writeFileSync(env.GITHUB_ENV, '');
  fs.writeFileSync(env.GITHUB_OUTPUT, '');
  const log = [];
  const io = {
    write: (s) => log.push({ kind: 'stdout', data: s }),
    append: (file, data) => {
      log.push({ kind: 'append', file, data });
      fs.appendFileSync(file, data);
    },
  };
  requests = [];
  return { env, io, log };
}

/** Parses NAME<<DELIM\nvalue\nDELIM blocks the way the runner does. */
function parseFileCommands(text) {
  const out = {};
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const m = /^([^<=]+)<<(.+)$/.exec(lines[i]);
    if (!m) continue;
    const [, name, delim] = m;
    const value = [];
    for (i++; lines[i] !== delim; i++) {
      assert.ok(i < lines.length, `unterminated ${name}`);
      value.push(lines[i]);
    }
    out[name] = value.join('\n');
  }
  return out;
}

describe('Poyesis/envault-action', () => {
  it('uses the hosted API when api-url is not given', async () => {
    const { env, io } = setup();
    delete env['INPUT_API-URL'];
    const urls = [];
    const fetchImpl = async (url, init) => {
      urls.push(String(url));
      if (String(url).startsWith(base)) return fetch(url, init); // GitHub's OIDC endpoint (the test server)
      if (String(url).endsWith('/v1/auth/oidc')) return new Response(JSON.stringify({ token: 'envault-session-token' }), { status: 200 });
      return new Response(JSON.stringify({ secrets: [] }), { status: 200 });
    };
    await run({ env, io, fetchImpl, retryBaseMs: 1 });
    assert.equal(DEFAULT_API_URL, 'https://api.envault.poyesis.fr');
    assert.deepEqual(urls.slice(1), [`${DEFAULT_API_URL}/v1/auth/oidc`, `${DEFAULT_API_URL}/v1/projects/${P}/envs/staging/secrets:resolve`]);
  });

  it('exchanges the OIDC token, masks every value before writing GITHUB_ENV', async () => {
    secrets = [
      { key: 'DB_URL', version: 3, value: 'postgres://u:p@db/x' },
      { key: 'PEM', version: 1, value: '-----BEGIN KEY-----\nabc123def\n-----END KEY-----' },
      { key: 'PCT', version: 1, value: '100%\rdone' },
    ];
    const { env, io, log } = setup({ audience: 'my-aud' });
    const loaded = await run({ env, io, fetchImpl: fetch, retryBaseMs: 1 });
    assert.deepEqual(loaded, ['DB_URL', 'PEM', 'PCT']);

    // OIDC audience and the exchange body.
    assert.equal(new URL(requests[0].url, 'http://x').searchParams.get('audience'), 'my-aud');
    assert.deepEqual(requests[1].body, { token: 'gh-oidc-jwt-my-aud' });
    assert.equal(requests[2].auth, 'Bearer envault-session-token');

    // Ordering: every mask command precedes the first file append.
    const firstAppend = log.findIndex((e) => e.kind === 'append');
    const masks = log.map((e, i) => [e, i]).filter(([e]) => e.kind === 'stdout' && e.data.startsWith('::add-mask::'));
    assert.ok(firstAppend > 0);
    assert.ok(masks.every(([, i]) => i < firstAppend));
    const masked = masks.map(([e]) => e.data);
    assert.ok(masked.includes('::add-mask::postgres://u:p@db/x\n'));
    assert.ok(masked.includes('::add-mask::-----BEGIN KEY-----%0Aabc123def%0A-----END KEY-----\n'));
    assert.ok(masked.includes('::add-mask::abc123def\n'), 'each line of a multi-line value is masked too');
    assert.ok(masked.includes('::add-mask::100%25%0Ddone\n'));
    assert.ok(masked.includes('::add-mask::envault-session-token\n'));

    // No value is ever printed outside a mask command.
    for (const e of log.filter((e) => e.kind === 'stdout' && !e.data.startsWith('::add-mask::'))) {
      for (const s of secrets) assert.ok(!e.data.includes(s.value), `value of ${s.key} leaked: ${e.data}`);
    }

    // GITHUB_ENV uses heredoc blocks with a random delimiter that round-trips values.
    const envText = fs.readFileSync(env.GITHUB_ENV, 'utf8');
    assert.match(envText, /^DB_URL<<ghadelimiter_[0-9a-f-]{36}\n/);
    assert.deepEqual(parseFileCommands(envText), { DB_URL: secrets[0].value, PEM: secrets[1].value, PCT: secrets[2].value });
    assert.deepEqual(parseFileCommands(fs.readFileSync(env.GITHUB_OUTPUT, 'utf8')), { keys: 'DB_URL,PEM,PCT' });
  });

  it('uses a different delimiter on each run', async () => {
    secrets = [{ key: 'A', version: 1, value: 'aaa' }];
    const a = setup();
    await run({ env: a.env, io: a.io, retryBaseMs: 1 });
    const b = setup();
    await run({ env: b.env, io: b.io, retryBaseMs: 1 });
    const delim = (f) => /<<(.+)\n/.exec(fs.readFileSync(f, 'utf8'))[1];
    assert.notEqual(delim(a.env.GITHUB_ENV), delim(b.env.GITHUB_ENV));
  });

  it('filters by keys, fails on missing keys, and can set outputs without exporting', async () => {
    secrets = [
      { key: 'A', version: 1, value: 'aaa' },
      { key: 'B', version: 1, value: 'bbb' },
    ];
    const { env, io } = setup({ keys: 'B', 'export-to-env': 'false', 'set-outputs': 'true' });
    assert.deepEqual(await run({ env, io, retryBaseMs: 1 }), ['B']);
    assert.equal(fs.readFileSync(env.GITHUB_ENV, 'utf8'), '');
    assert.deepEqual(parseFileCommands(fs.readFileSync(env.GITHUB_OUTPUT, 'utf8')), { B: 'bbb', keys: 'B' });

    const m = setup({ keys: 'A, NOPE\nB' });
    await assert.rejects(run({ env: m.env, io: m.io, retryBaseMs: 1 }), /not found in staging: NOPE/);
    assert.equal(fs.readFileSync(m.env.GITHUB_ENV, 'utf8'), '');
  });

  it('rejects invalid names and skips reserved runner variables', async () => {
    secrets = [{ key: 'NODE_OPTIONS', version: 1, value: '--require /tmp/x.js' }, { key: 'OK', version: 1, value: 'fine' }];
    const r = setup();
    assert.deepEqual(await run({ env: r.env, io: r.io, retryBaseMs: 1 }), ['OK']);
    assert.ok(r.log.some((e) => e.data && e.data.startsWith('::warning::skipping NODE_OPTIONS')));
    assert.ok(!fs.readFileSync(r.env.GITHUB_ENV, 'utf8').includes('NODE_OPTIONS'));

    secrets = [{ key: 'BAD-NAME', version: 1, value: 'x' }];
    const b = setup();
    await assert.rejects(run({ env: b.env, io: b.io, retryBaseMs: 1 }), /not a valid environment variable name/);
  });

  it('skips every reserved name (loader, interpreter, shell, runner) from $GITHUB_ENV', async () => {
    const reserved = ['LD_PRELOAD', 'BASH_ENV', 'ENV', 'JAVA_TOOL_OPTIONS', 'PYTHONPATH', 'PERL5OPT', 'DYLD_INSERT_LIBRARIES',
      'GIT_SSH_COMMAND', 'GITHUB_PATH', 'RUNNER_TEMP', 'ACTIONS_RUNTIME_TOKEN', 'PATH', 'CI', 'ld_preload'];
    secrets = [...reserved.map((key) => ({ key, version: 1, value: 'x' })), { key: 'DATABASE_URL', version: 1, value: 'db' }];
    const r = setup();
    assert.deepEqual(await run({ env: r.env, io: r.io, retryBaseMs: 1 }), ['DATABASE_URL']);
    const written = parseFileCommands(fs.readFileSync(r.env.GITHUB_ENV, 'utf8'));
    assert.deepEqual(Object.keys(written), ['DATABASE_URL']);
    for (const k of reserved) assert.ok(r.log.some((e) => e.data && e.data.startsWith(`::warning::skipping ${k}:`)), k);
    for (const k of ['DATABASE_URL', 'ENVIRONMENT', 'HOMEPAGE', 'GIT_AUTHOR_NAME', 'NODE_ENV']) assert.equal(isReservedEnvName(k), false, k);
  });

  it('refuses values that contain the delimiter', () => {
    assert.throws(() => fileCommandEntry('A', 'x\nDELIM\ny', 'DELIM'), ActionError);
    assert.equal(fileCommandEntry('A', 'v', 'D'), 'A<<D\nv\nD\n');
  });

  it('retries 5xx from the API', async () => {
    secrets = [{ key: 'A', version: 1, value: 'aaa' }];
    failResolve = 2;
    const { env, io } = setup();
    assert.deepEqual(await run({ env, io, retryBaseMs: 1 }), ['A']);
    assert.equal(requests.filter((r) => r.url.includes('secrets:resolve')).length, 3);
  });

  it('explains missing id-token permission', async () => {
    const { env, io } = setup();
    delete env.ACTIONS_ID_TOKEN_REQUEST_URL;
    await assert.rejects(run({ env, io }), /id-token: write/);
  });

  it('mask commands escape and split values', () => {
    assert.deepEqual(maskCommands(''), []);
    assert.deepEqual(maskCommands('a%b'), ['::add-mask::a%25b']);
    assert.deepEqual(maskCommands('line-one\nx\nline-two'), ['::add-mask::line-one%0Ax%0Aline-two', '::add-mask::line-one', '::add-mask::line-two']);
  });

  it('runs as the action entrypoint and reports errors as ::error::', async () => {
    secrets = [{ key: 'A', version: 1, value: 'aaa' }];
    const { env } = setup();
    const { stdout } = await promisify(execFile)(process.execPath, [ENTRY], { env: { ...env, PATH: process.env.PATH } });
    assert.match(stdout, /::add-mask::aaa\n[\s\S]*Loaded 1 secret\(s\) from staging: A/);
    assert.match(fs.readFileSync(env.GITHUB_ENV, 'utf8'), /^A<<ghadelimiter_.+\naaa\n/);

    const bad = setup();
    delete bad.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
    const err = await promisify(execFile)(process.execPath, [ENTRY], { env: { ...bad.env, PATH: process.env.PATH } }).catch((e) => e);
    assert.equal(err.code, 1);
    assert.match(err.stdout, /^::error::GitHub OIDC is not available/);
  });
});
