import fs from 'node:fs';
import path from 'node:path';

const [recordPath, revealedPath, hashPath, storeDir] = process.argv.slice(2);

if (!recordPath || !revealedPath || !hashPath || !storeDir) {
  throw new Error('usage: vault-smoke-check.mjs <record> <revealed> <hash> <store-dir>');
}

const record = JSON.parse(fs.readFileSync(recordPath, 'utf8'));
const revealed = JSON.parse(fs.readFileSync(revealedPath, 'utf8'));
const hash = JSON.parse(fs.readFileSync(hashPath, 'utf8'));

if (record.artifact_type !== 'cred.artifact_record') {
  throw new Error(`unexpected record artifact_type: ${record.artifact_type}`);
}
if (record.custody !== 'local_encrypted') {
  throw new Error(`unexpected custody: ${record.custody}`);
}
if (!record.artifact_uri?.startsWith('cred-vault://blobs/')) {
  throw new Error(`unexpected artifact_uri: ${record.artifact_uri}`);
}
if (record.stored_artifact_type !== 'witness.signed_attestation') {
  throw new Error(`unexpected stored_artifact_type: ${record.stored_artifact_type}`);
}
if (revealed.artifact_type !== 'witness.signed_attestation') {
  throw new Error(`unexpected revealed artifact_type: ${revealed.artifact_type}`);
}
if (hash.artifact_hash !== record.artifact_hash) {
  throw new Error('revealed artifact hash does not match encrypted record hash');
}

const blobsDir = path.join(storeDir, 'blobs');
const blobFiles = fs.readdirSync(blobsDir);
if (blobFiles.length !== 1) {
  throw new Error(`expected one encrypted blob, got ${blobFiles.length}`);
}
const blobText = fs.readFileSync(path.join(blobsDir, blobFiles[0]), 'utf8');
if (!blobText.includes('cred.encrypted_artifact_blob')) {
  throw new Error('blob header missing encrypted artifact type');
}
if (blobText.includes('"tree_size"') || blobText.includes('"signatures"')) {
  throw new Error('encrypted blob appears to contain plaintext Witness fields');
}

console.log('Cred encrypted vault smoke passed.');
