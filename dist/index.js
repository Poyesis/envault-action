'use strict';
// Poyesis/envault-action: single dependency-free file run by the node24 runtime.
// Flow: GitHub OIDC token -> POST /v1/auth/oidc -> GET secrets:resolve ->
// ::add-mask:: every value -> $GITHUB_ENV / $GITHUB_OUTPUT.

const crypto = require('node:crypto');
const fs = require('node:fs');

/** The hosted Envault API; self-hosted servers pass api-url. */
const DEFAULT_API_URL = 'https://api.envault.poyesis.fr';

class ActionError extends Error {}

/** Reads an action input the way the runner exposes it (INPUT_<NAME>, uppercased, spaces -> _). */
function getInput(env, name, fallback = '') {
  const v = env[`INPUT_${name.replace(/ /g, '_').toUpperCase()}`];
  return v === undefined || v.trim() === '' ? fallback : v.trim();
}

function getBool(env, name, fallback) {
  const v = getInput(env, name, String(fallback)).toLowerCase();
  if (['true', 'yes', '1'].includes(v)) return true;
  if (['false', 'no', '0'].includes(v)) return false;
  throw new ActionError(`input ${name} must be true or false`);
}

/** Escaping for workflow command data (same rules as @actions/core). */
function escapeData(s) {
  return String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

/**
 * Mask commands for a value: the whole value (escaped, so multi-line values
 * are one mask) plus each line, because the runner masks per log line.
 */
function maskCommands(value) {
  if (!value) return [];
  const cmds = [`::add-mask::${escapeData(value)}`];
  if (/[\r\n]/.test(value)) {
    for (const line of value.split(/\r?\n/)) {
      if (line.trim().length >= 3) cmds.push(`::add-mask::${escapeData(line)}`);
    }
  }
  return cmds;
}

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

// Names a secret must never set for later steps: they change how programs start (loader, interpreter and
// shell hooks), where they look for code, or how the runner behaves.
// KEEP IN SYNC with RESERVED_KEY_NAMES / RESERVED_KEY_PREFIXES in apps/api/src/keys/reserved.ts (source of truth) and the copies in
// packages/cli/src/reserved.ts, packages/sdk-node/src/reserved.ts and packages/sdk-python (RESERVED_ENV_NAMES).
const RESERVED_ENV_NAMES = [
  'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT',
  'BASH_ENV', 'ENV', 'SHELL', 'IFS', 'PS4', 'PROMPT_COMMAND',
  'NODE_OPTIONS', 'NODE_PATH',
  'PYTHONPATH', 'PYTHONSTARTUP', 'PYTHONHOME',
  'PERL5OPT', 'PERL5LIB', 'RUBYOPT',
  'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS',
  'PATH', 'HOME',
  'GIT_SSH', 'GIT_SSH_COMMAND',
  'GCONV_PATH',
];
const RESERVED_ENV_PREFIXES = ['DYLD_', 'MALLOC_', 'GITHUB_', 'RUNNER_', 'ACTIONS_'];
/** Runner-specific additions: CI changes how many tools behave. */
const RUNNER_ONLY = ['CI'];

/** True for names that must not be exported (case-insensitive: Windows runners compare env names that way). */
function isReservedEnvName(name) {
  const n = String(name).toUpperCase();
  if (RESERVED_ENV_NAMES.includes(n) || RUNNER_ONLY.includes(n)) return true;
  if (RESERVED_ENV_PREFIXES.some((p) => n.startsWith(p))) return true;
  return n.startsWith('GIT_') && n.includes('SSH');
}

/** One NAME<<DELIM ... DELIM block. The delimiter is random and may not occur in name or value. */
function fileCommandEntry(name, value, delimiter) {
  if (name.includes(delimiter) || value.includes(delimiter)) {
    throw new ActionError(`${name}: value contains the file-command delimiter; refusing to write it`);
  }
  return `${name}<<${delimiter}\n${value}\n${delimiter}\n`;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function requestJson(fetchImpl, url, init, { retries = 3, retryBaseMs = 500, what }) {
  for (let attempt = 0; ; attempt++) {
    let res;
    try {
      res = await fetchImpl(url, { ...init, signal: AbortSignal.timeout(15_000) });
    } catch {
      if (attempt < retries) {
        await sleep(retryBaseMs * 2 ** attempt);
        continue;
      }
      throw new ActionError(`${what}: cannot reach ${new URL(url).origin}`);
    }
    const body = await res.json().catch(() => ({}));
    if (res.ok) return body;
    if ((res.status === 429 || res.status >= 500) && attempt < retries) {
      const ra = Number(res.headers.get('retry-after'));
      await sleep(res.headers.has('retry-after') && Number.isFinite(ra) ? Math.min(ra * 1000, 60_000) : retryBaseMs * 2 ** attempt);
      continue;
    }
    const msg = body && typeof body.message === 'string' ? body.message : `HTTP ${res.status}`;
    const rid = body && typeof body.requestId === 'string' ? ` (request ${body.requestId})` : '';
    throw new ActionError(`${what} failed (HTTP ${res.status}): ${msg}${rid}`);
  }
}

async function githubOidcToken(env, audience, fetchImpl, opts) {
  const url = env.ACTIONS_ID_TOKEN_REQUEST_URL;
  const bearer = env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!url || !bearer) {
    throw new ActionError('GitHub OIDC is not available. Add `permissions: id-token: write` to the job (or workflow).');
  }
  const u = new URL(url);
  u.searchParams.set('audience', audience);
  const body = await requestJson(fetchImpl, u.toString(), { headers: { authorization: `Bearer ${bearer}`, accept: 'application/json' } }, {
    ...opts,
    what: 'GitHub OIDC token request',
  });
  if (!body || typeof body.value !== 'string') throw new ActionError('GitHub OIDC response had no token');
  return body.value;
}

function parseKeys(raw) {
  return raw
    .split(/[,\n]/)
    .map((k) => k.trim())
    .filter(Boolean);
}

/**
 * Runs the action. Everything external is injectable for tests:
 * env (inputs + runner variables), fetch, and io (stdout + file appends).
 */
async function run({
  env = process.env,
  fetchImpl = globalThis.fetch,
  io = { write: (s) => process.stdout.write(s), append: (file, data) => fs.appendFileSync(file, data, { encoding: 'utf8' }) },
  retryBaseMs = 500,
} = {}) {
  const apiUrl = getInput(env, 'api-url', DEFAULT_API_URL).replace(/\/+$/, '');
  const projectId = getInput(env, 'project-id');
  const environment = getInput(env, 'environment');
  if (!apiUrl || !projectId || !environment) throw new ActionError('project-id and environment are required');
  const audience = getInput(env, 'audience', 'envault');
  const exportToEnv = getBool(env, 'export-to-env', true);
  const mask = getBool(env, 'mask', true);
  const setOutputs = getBool(env, 'set-outputs', false);
  const wanted = parseKeys(getInput(env, 'keys'));
  const reqOpts = { retryBaseMs };

  const oidc = await githubOidcToken(env, audience, fetchImpl, reqOpts);
  io.write(`::add-mask::${escapeData(oidc)}\n`);

  const exchanged = await requestJson(
    fetchImpl,
    `${apiUrl}/v1/auth/oidc`,
    { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify({ token: oidc }) },
    { ...reqOpts, what: 'Envault token exchange' },
  );
  if (!exchanged || typeof exchanged.token !== 'string') throw new ActionError('Envault token exchange returned no token');
  io.write(`::add-mask::${escapeData(exchanged.token)}\n`);

  const resolved = await requestJson(
    fetchImpl,
    `${apiUrl}/v1/projects/${encodeURIComponent(projectId)}/envs/${encodeURIComponent(environment)}/secrets:resolve`,
    { headers: { authorization: `Bearer ${exchanged.token}`, accept: 'application/json' } },
    { ...reqOpts, what: 'Envault resolve' },
  );
  let secrets = Array.isArray(resolved && resolved.secrets) ? resolved.secrets : [];
  if (wanted.length) {
    const have = new Set(secrets.map((s) => s.key));
    const missing = wanted.filter((k) => !have.has(k));
    if (missing.length) throw new ActionError(`not found in ${environment}: ${missing.join(', ')}`);
    const set = new Set(wanted);
    secrets = secrets.filter((s) => set.has(s.key));
  }

  // 1. Mask everything before any value reaches a file the runner might echo.
  if (mask) {
    for (const s of secrets) for (const cmd of maskCommands(String(s.value))) io.write(`${cmd}\n`);
  } else {
    io.write('::warning::mask is false: secret values may appear in logs\n');
  }

  // 2. Validate names and build file-command payloads (all-or-nothing).
  const delimiter = `ghadelimiter_${crypto.randomUUID()}`;
  let envData = '';
  let outData = '';
  const loaded = [];
  for (const s of secrets) {
    const value = String(s.value);
    if (!ENV_NAME.test(s.key)) throw new ActionError(`${s.key} is not a valid environment variable name`);
    if (exportToEnv && isReservedEnvName(s.key)) {
      io.write(`::warning::skipping ${s.key}: reserved variable name (it could change how later steps run)\n`);
      continue;
    }
    if (exportToEnv) envData += fileCommandEntry(s.key, value, delimiter);
    if (setOutputs) outData += fileCommandEntry(s.key, value, delimiter);
    loaded.push(s.key);
  }
  outData += fileCommandEntry('keys', loaded.join(','), delimiter);

  // 3. Write.
  if (exportToEnv && envData) {
    if (!env.GITHUB_ENV) throw new ActionError('GITHUB_ENV is not set (not running on a GitHub runner?)');
    io.append(env.GITHUB_ENV, envData);
  }
  if (env.GITHUB_OUTPUT) io.append(env.GITHUB_OUTPUT, outData);

  io.write(`Loaded ${loaded.length} secret(s) from ${environment}: ${loaded.join(', ') || '(none)'}\n`);
  return loaded;
}

module.exports = { run, DEFAULT_API_URL, maskCommands, escapeData, fileCommandEntry, parseKeys, isReservedEnvName, ActionError };

if (require.main === module) {
  run().catch((err) => {
    const msg = err instanceof ActionError ? err.message : `unexpected error: ${err && err.message ? err.message : String(err)}`;
    process.stdout.write(`::error::${escapeData(msg)}\n`);
    process.exitCode = 1;
  });
}
