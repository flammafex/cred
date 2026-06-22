import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const [bin, storeDir, rootDir, portArg] = process.argv.slice(2);

if (!bin || !storeDir || !rootDir) {
  throw new Error('usage: http-service-smoke.mjs <cred-bin> <store-dir> <repo-root> [port]');
}

const port = portArg && portArg !== '0' ? portArg : '7331';

const service = spawn(bin, ['--store', storeDir, 'serve', 'http', '--port', port], {
  stdio: ['pipe', 'pipe', 'pipe'],
});

let stderr = '';
service.stderr.on('data', chunk => {
  stderr += chunk;
});

// Wait for the service to start listening.
await new Promise(resolve => {
  service.stderr.on('data', chunk => {
    if (chunk.toString().includes('listening')) {
      resolve();
    }
  });
});

// Give the server a moment to fully bind.
await new Promise(resolve => setTimeout(resolve, 100));

const baseUrl = `http://127.0.0.1:${port}`;

function readFixture(name) {
  return JSON.parse(
    fs.readFileSync(path.join(rootDir, 'examples/stdio-service', name), 'utf8').trim()
  );
}

// Reuse the stdio service request fixtures (same JSON envelope).
const requestLines = fs
  .readFileSync(path.join(rootDir, 'examples/stdio-service/requests.jsonl'), 'utf8')
  .trim()
  .split('\n')
  .map(line => JSON.parse(line));

const responses = [];
for (const request of requestLines) {
  const res = await fetch(baseUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  });
  if (!res.ok) {
    throw new Error(`HTTP ${res.status} for request ${request.id}`);
  }
  responses.push(await res.json());
}

// Stop the service.
service.kill('SIGTERM');

const exitCode = await new Promise(resolve => {
  service.on('close', resolve);
});

if (exitCode !== null && exitCode !== 0) {
  throw new Error(`http service exited with ${exitCode}: ${stderr}`);
}

const byId = new Map(responses.map(response => [response.id, response]));

function result(id) {
  const response = byId.get(id);
  if (!response) {
    throw new Error(`missing response for ${id}`);
  }
  if (response.artifact_type !== 'cred.service_response') {
    throw new Error(`unexpected service response artifact_type: ${response.artifact_type}`);
  }
  if (response.ok !== true) {
    throw new Error(`request ${id} failed: ${response.error?.message}`);
  }
  return response.result;
}

const info = result('info');
if (!info.methods?.includes('cred.present') || info.transport !== 'http') {
  throw new Error('service info did not advertise http presentation support');
}
if (info.methods?.includes('cred.grant_approve')) {
  throw new Error('service info must not advertise grant_approve on http channel');
}

const review = result('review');
if (review.artifact_type !== 'cred.grant_review') {
  throw new Error(`unexpected review artifact_type: ${review.artifact_type}`);
}
if (review.warnings?.includes('Grant does not bind an app public key.') !== true) {
  throw new Error('grant review did not include expected app public key warning');
}

const imported = result('import');
if (imported.artifact_type !== 'cred.stored_grant') {
  throw new Error(`unexpected imported grant artifact_type: ${imported.artifact_type}`);
}

const presentation = result('present');
const artifact = presentation.artifacts?.[0];
if (presentation.artifact_type !== 'cred.presentation') {
  throw new Error(`unexpected presentation artifact_type: ${presentation.artifact_type}`);
}
if (presentation.cred_signature?.scheme !== 'ed25519') {
  throw new Error('http presentation was not signed');
}
if (artifact?.disclosure !== 'embedded' || artifact.artifact?.artifact_type !== 'witness.signed_attestation') {
  throw new Error('http presentation did not embed the Witness attestation');
}

const inventory = result('inventory');
if (inventory.total_grants !== 1 || inventory.total_grant_approvals !== 1) {
  throw new Error('inventory did not include the http grant and approval records');
}
if (inventory.total_presentations !== 1 || inventory.disclosure_modes?.embedded !== 1) {
  throw new Error('inventory did not include the http presentation audit');
}
if (inventory.presentations?.[0]?.approval_id !== 'approval-stdio-witness-1') {
  throw new Error('presentation audit did not retain the CLI approval id');
}

console.log('Cred HTTP service smoke passed.');
