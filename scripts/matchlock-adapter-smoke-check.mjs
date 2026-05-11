import fs from 'node:fs';

const [recordPath, presentationPath, verifyPath] = process.argv.slice(2);

if (!recordPath || !presentationPath || !verifyPath) {
  throw new Error('usage: matchlock-adapter-smoke-check.mjs <record> <presentation> <verify>');
}

const record = JSON.parse(fs.readFileSync(recordPath, 'utf8'));
const presentation = JSON.parse(fs.readFileSync(presentationPath, 'utf8'));
const verification = JSON.parse(fs.readFileSync(verifyPath, 'utf8'));
const artifact = presentation.artifacts?.[0];

if (record.artifact_type !== 'cred.artifact_record') {
  throw new Error(`unexpected record artifact_type: ${record.artifact_type}`);
}
if (record.stored_artifact_type !== 'matchlock.commitment') {
  throw new Error(`unexpected stored_artifact_type: ${record.stored_artifact_type}`);
}
if (record.labels?.includes('matchlock') !== true) {
  throw new Error('Matchlock record is missing matchlock label');
}
if (artifact?.artifact_type !== 'matchlock.commitment') {
  throw new Error(`unexpected presented artifact_type: ${artifact?.artifact_type}`);
}
if (artifact.record_id !== record.record_id) {
  throw new Error(`presentation record_id ${artifact.record_id} did not match ${record.record_id}`);
}
if (artifact.artifact_hash !== record.artifact_hash) {
  throw new Error('presentation artifact_hash did not match stored Matchlock record hash');
}
if (artifact.disclosure !== 'reference') {
  throw new Error(`unexpected disclosure: ${artifact.disclosure}`);
}
if (artifact.artifact !== undefined) {
  throw new Error('record-backed Matchlock presentation embedded raw selection material');
}
if (presentation.cred_signature?.scheme !== 'ed25519') {
  throw new Error('presentation was not signed with an Ed25519 Cred signature');
}
if (verification.verified !== true) {
  throw new Error('Cred signature verification did not pass');
}

console.log('Cred Matchlock adapter smoke passed.');
