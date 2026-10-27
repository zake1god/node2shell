// Orbital - a (fictional) bulk data-ingestion platform.
//
// This is the CVE-2026-111497 ("node2shell") lab fixture, shaped like a real
// product so the vulnerability sits where it realistically would: on a bulk
// IMPORT endpoint that accepts large, compressed batches. Express 5 /
// body-parser 2.x decode `Content-Encoding: br` request bodies transparently,
// so the bundled Brotli decoder runs on client bytes with no special handling.
//
//   inbound  - POST /api/v1/import accepts a large br-compressed JSON batch
//              (50 MB limit, scoped to this route only) -> vulnerable decoder.
//   outbound - GET /api/v1/unfurl?url= fetches a remote URL (accept br) and
//              decodes the response -> vulnerable decoder on remote content.
//
// Other routes keep the default 100 KB body limit, like a normal app: the big
// limit lives only where a bulk importer would really put it. Run on
// node:24.22.0 (vulnerable) vs 24.22.1 (fixed) for an A/B pair.

const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const { execFile } = require('child_process');
const express = require('express');

const app = express();
app.disable('x-powered-by');

// tiny request log (no dependency) - realistic access logging
app.use((req, _res, next) => {
  const id = Math.random().toString(16).slice(2, 10);
  req.reqId = id;
  console.log(`[${new Date().toISOString()}] ${id} ${req.method} ${req.url}`);
  next();
});

app.use(express.static(path.join(__dirname, 'public'), { extensions: ['html'] }));

// ---- in-memory store (demo data) ------------------------------------------
const datasets = [
  { id: 'ds_tx', name: 'Transactions', records: 1_284_339, updated: '2026-10-22' },
  { id: 'ds_mch', name: 'Merchants', records: 48_221, updated: '2026-10-23' },
  { id: 'ds_fx', name: 'FX rates', records: 9_410, updated: '2026-10-24' },
];
const imports = [];
let jobSeq = 1000;

// ---- API ------------------------------------------------------------------
const health = (_req, res) => res.type('text/plain').send('PONG\n');
app.get('/health', health);
app.get('/healthz', health);

app.get('/api/v1/version', (_req, res) =>
  res.json({ service: 'orbital', node: process.version }));

// normal routes: default 100 KB limit, like any ordinary JSON API
const smallJson = express.json();

app.get('/api/v1/datasets', (_req, res) => res.json({ datasets }));

app.post('/api/v1/datasets', smallJson, (req, res) => {
  const name = (req.body && req.body.name) || 'Untitled';
  const ds = { id: 'ds_' + (Math.random().toString(16).slice(2, 6)), name, records: 0,
               updated: new Date().toISOString().slice(0, 10) };
  datasets.push(ds);
  res.status(201).json({ dataset: ds });
});

app.get('/api/v1/imports', (_req, res) => res.json({ imports }));

// THE BULK IMPORT ENDPOINT - large, compressed batches land here.
// A 50 MB limit is scoped to just this route (as a real bulk importer would),
// and body-parser transparently inflates `Content-Encoding: br` into the
// vulnerable decoder before our handler ever runs.
const bulkJson = express.json({ limit: '50mb' });

app.post('/api/v1/import', bulkJson, (req, res) => {
  const body = req.body || {};
  const count = Array.isArray(body.records) ? body.records.length : 0;
  const job = {
    jobId: 'job_' + (jobSeq++),
    dataset: body.dataset || 'ds_tx',
    status: 'queued',
    records: count,
    node: process.version,
    receivedAt: new Date().toISOString(),
  };
  imports.unshift(job);
  if (imports.length > 25) imports.pop();
  res.status(202).json(job); // 202 Accepted - queued for processing
});

// Post-exploitation lab console. This route is deliberately locked until the
// exploited Node worker executes /activate. The helper creates a
// random token inside the container and returns the same token over the ROP
// socket. The patched control never enables this route.
const shellForm = express.urlencoded({ extended: false, limit: '8kb' });
const shellTokenFile = '/tmp/node2shell-shell.enabled';
const shellDefaultCwd = '/app';
const shellMaxCommandBytes = 4096;
const shellMaxOutputBytes = 1024 * 1024;

function shellDeny(res, status, message) {
  res.status(status).type('text/plain').send(message + '\n');
}

function tokensMatch(expected, supplied) {
  const left = Buffer.from(expected.trim(), 'utf8');
  const right = Buffer.from(supplied.trim(), 'utf8');
  return left.length > 0 && left.length === right.length &&
    crypto.timingSafeEqual(left, right);
}

app.post('/api/v1/shell', shellForm, (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.set('X-Content-Type-Options', 'nosniff');

  if (process.env.LAB_VARIANT !== 'vulnerable') {
    return shellDeny(res, 403, 'The target-backed shell is disabled on this control.');
  }

  let expectedToken;
  try {
    expectedToken = fs.readFileSync(shellTokenFile, 'utf8');
  } catch (_error) {
    return shellDeny(res, 403, 'Shell locked: a successful local RCE proof is required.');
  }

  const suppliedToken = String(req.get('X-Lab-Token') || '');
  if (!tokensMatch(expectedToken, suppliedToken)) {
    return shellDeny(res, 403, 'Shell locked: a successful local RCE proof is required.');
  }

  const command = typeof req.body.cmd === 'string' ? req.body.cmd : '';
  if (!command.trim()) {
    return shellDeny(res, 400, 'A non-empty cmd field is required.');
  }
  if (Buffer.byteLength(command, 'utf8') > shellMaxCommandBytes) {
    return shellDeny(res, 413, 'Command exceeds the 4096-byte lab limit.');
  }

  const requestedCwd = typeof req.body.cwd === 'string' && req.body.cwd
    ? req.body.cwd : shellDefaultCwd;
  let cwd;
  try {
    cwd = fs.realpathSync(requestedCwd);
    if (!fs.statSync(cwd).isDirectory()) throw new Error('not a directory');
    fs.accessSync(cwd, fs.constants.R_OK | fs.constants.X_OK);
  } catch (_error) {
    return shellDeny(res, 400, 'Working directory is not accessible to the Node worker.');
  }

  execFile(
    '/usr/bin/timeout',
    ['--signal=KILL', '10s', '/bin/sh', '-lc', command],
    { cwd, encoding: 'utf8', maxBuffer: shellMaxOutputBytes },
    (error, stdout, stderr) => {
      const exitCode = error && Number.isInteger(error.code) ? error.code : 0;
      res.set('X-Zarxec-Exit-Code', String(exitCode));
      res.set('X-Zarxec-Cwd', encodeURIComponent(cwd));
      res.type('text/plain').send(String(stdout || '') + String(stderr || ''));
    },
  );
});

// outbound fetch surface - link/url unfurl, decodes a br response
app.get('/api/v1/unfurl', async (req, res) => {
  const target = String(req.query.url || '');
  if (!/^https?:\/\//.test(target)) {
    return res.status(400).json({ error: 'url query param (http/https) required' });
  }
  try {
    const upstream = await fetch(target, { headers: { 'accept-encoding': 'br' } });
    const text = await upstream.text(); // Node decodes br here
    res.json({ ok: true, status: upstream.status, bytes: text.length,
               title: (text.match(/<title[^>]*>([^<]*)<\/title>/i) || [, ''])[1].trim() });
  } catch (err) {
    res.status(502).json({ ok: false, error: String(err) });
  }
});

// JSON error handler LAST - surfaces body-parser/zlib decode errors so the
// vuln/fixed divergence is observable remotely (24.22.0 continues; 24.22.1
// rejects with ERR__ERROR_FORMAT_BLOCK_SWITCH).
app.use((err, req, res, _next) => {
  res.status(err.status || 400)
     .json({ error: String(err.message || err), code: err.code || null });
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => console.log(`[orbital] node ${process.version} listening on :${port}`));
