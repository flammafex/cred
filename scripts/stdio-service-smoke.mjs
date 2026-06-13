import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const [bin, storeDir, rootDir] = process.argv.slice(2);

if (!bin || !storeDir || !rootDir) {
  throw new Error('usage: stdio-service-smoke.mjs <cred-bin> <store-dir> <repo-root>');
}

const grant = JSON.parse(
  fs.readFileSync(path.join(rootDir, 'examples/witness-permission-grant.json'), 'utf8'),
);
const request = JSON.parse(
  fs.readFileSync(path.join(rootDir, 'examples/witness-presentation-request.json'), 'utf8'),
);
const attestation = JSON.parse(
  fs.readFileSync(path.join(rootDir, 'examples/witness-signed-attestation.json'), 'utf8'),
);

const service = spawn(bin, ['--store', storeDir, 'serve', 'stdio'], {
  stdio: ['pipe', 'pipe', 'pipe'],
});

let stdout = '';
let stderr = '';
service.stdout.on('data', chunk => {
  stdout += chunk;
});
service.stderr.on('data', chunk => {
  stderr += chunk;
});

const requests = [
  {
    id: 'info',
    method: 'cred.service_info',
  },
  {
    id: 'review',
    method: 'cred.grant_review',
    params: { grant },
  },
  {
    id: 'import',
    method: 'cred.grant_import',
    params: {
      grant,
      source_uri: 'examples/witness-permission-grant.json',
    },
  },
  {
    id: 'approve',
    method: 'cred.grant_approve',
    params: {
      grant,
      approval_id: 'approval-stdio-witness-1',
      reviewer: 'stdio-smoke',
      note: 'approved by stdio smoke',
      source_uri: 'examples/witness-permission-grant.json',
    },
  },
  {
    id: 'present',
    method: 'cred.present',
    params: {
      request,
      grant,
      approval_id: 'approval-stdio-witness-1',
      artifact: attestation,
      disclosure: 'embedded',
      presentation_id: 'presentation-stdio-witness-1',
      cred_id: 'cred:local:example',
    },
  },
  {
    id: 'inventory',
    method: 'cred.vault_inventory',
  },
];

for (const request of requests) {
  service.stdin.write(`${JSON.stringify(request)}\n`);
}
service.stdin.end();

const exitCode = await new Promise(resolve => {
  service.on('close', resolve);
});

if (exitCode !== 0) {
  throw new Error(`stdio service exited with ${exitCode}: ${stderr}`);
}

const responses = stdout
  .trim()
  .split('\n')
  .filter(Boolean)
  .map(line => JSON.parse(line));
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
if (!info.methods?.includes('cred.present') || info.transport !== 'stdio') {
  throw new Error('service info did not advertise stdio presentation support');
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

const approval = result('approve');
if (approval.artifact_type !== 'cred.grant_approval' || approval.decision !== 'approved') {
  throw new Error('grant approval response was not approved');
}
if (approval.grant_hash !== imported.grant_hash) {
  throw new Error('approval hash does not match imported grant hash');
}

const presentation = result('present');
const artifact = presentation.artifacts?.[0];
if (presentation.artifact_type !== 'cred.presentation') {
  throw new Error(`unexpected presentation artifact_type: ${presentation.artifact_type}`);
}
if (presentation.cred_signature?.scheme !== 'ed25519') {
  throw new Error('stdio presentation was not signed');
}
if (artifact?.disclosure !== 'embedded' || artifact.artifact?.artifact_type !== 'witness.signed_attestation') {
  throw new Error('stdio presentation did not embed the Witness attestation');
}

const inventory = result('inventory');
if (inventory.total_grants !== 1 || inventory.total_grant_approvals !== 1) {
  throw new Error('inventory did not include the stdio grant and approval records');
}
if (inventory.total_presentations !== 1 || inventory.disclosure_modes?.embedded !== 1) {
  throw new Error('inventory did not include the stdio presentation audit');
}
if (inventory.presentations?.[0]?.approval_id !== approval.approval_id) {
  throw new Error('presentation audit did not retain the stdio approval id');
}

console.log('Cred stdio service smoke passed.');
