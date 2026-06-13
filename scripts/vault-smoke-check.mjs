import fs from 'node:fs';
import path from 'node:path';

const [
  grantReviewPath,
  grantPath,
  grantGetPath,
  grantApprovalPath,
  grantApprovalGetPath,
  recordPath,
  revealedPath,
  hashPath,
  presentationPath,
  verifyPath,
  inventoryPath,
  storeDir,
] = process.argv.slice(2);

if (
  !grantReviewPath ||
  !grantPath ||
  !grantGetPath ||
  !grantApprovalPath ||
  !grantApprovalGetPath ||
  !recordPath ||
  !revealedPath ||
  !hashPath ||
  !presentationPath ||
  !verifyPath ||
  !inventoryPath ||
  !storeDir
) {
  throw new Error(
    'usage: vault-smoke-check.mjs <grant-review> <grant> <grant-get> <grant-approval> <grant-approval-get> <record> <revealed> <hash> <presentation> <verify> <inventory> <store-dir>',
  );
}

const grantReview = JSON.parse(fs.readFileSync(grantReviewPath, 'utf8'));
const grant = JSON.parse(fs.readFileSync(grantPath, 'utf8'));
const grantGet = JSON.parse(fs.readFileSync(grantGetPath, 'utf8'));
const grantApproval = JSON.parse(fs.readFileSync(grantApprovalPath, 'utf8'));
const grantApprovalGet = JSON.parse(fs.readFileSync(grantApprovalGetPath, 'utf8'));
const record = JSON.parse(fs.readFileSync(recordPath, 'utf8'));
const revealed = JSON.parse(fs.readFileSync(revealedPath, 'utf8'));
const hash = JSON.parse(fs.readFileSync(hashPath, 'utf8'));
const presentation = JSON.parse(fs.readFileSync(presentationPath, 'utf8'));
const verify = JSON.parse(fs.readFileSync(verifyPath, 'utf8'));
const inventory = JSON.parse(fs.readFileSync(inventoryPath, 'utf8'));

if (grantReview.artifact_type !== 'cred.grant_review') {
  throw new Error(`unexpected grant review artifact_type: ${grantReview.artifact_type}`);
}
if (grantReview.warnings?.includes('Grant does not bind an app public key.') !== true) {
  throw new Error('grant review did not include expected app public key warning');
}
if (grant.artifact_type !== 'cred.stored_grant') {
  throw new Error(`unexpected stored grant artifact_type: ${grant.artifact_type}`);
}
if (grant.grant_id !== 'grant-witness-attestation-1') {
  throw new Error(`unexpected grant_id: ${grant.grant_id}`);
}
if (grantGet.grant_hash !== grant.grant_hash) {
  throw new Error('grant get did not return the imported grant');
}
if (grantApproval.artifact_type !== 'cred.grant_approval') {
  throw new Error(`unexpected grant approval artifact_type: ${grantApproval.artifact_type}`);
}
if (grantApproval.decision !== 'approved') {
  throw new Error(`unexpected grant approval decision: ${grantApproval.decision}`);
}
if (grantApproval.grant_hash !== grant.grant_hash) {
  throw new Error('grant approval hash does not match imported grant hash');
}
if (grantApprovalGet.approval_id !== grantApproval.approval_id) {
  throw new Error('grant approval get did not return the approval record');
}
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
if (presentation.artifact_type !== 'cred.presentation') {
  throw new Error(`unexpected presentation artifact_type: ${presentation.artifact_type}`);
}
if (presentation.artifacts?.[0]?.record_id !== record.record_id) {
  throw new Error('presentation did not reference the encrypted record');
}
if (presentation.artifacts?.[0]?.artifact) {
  throw new Error('record-backed presentation embedded the raw artifact');
}
if (verify.verified !== true) {
  throw new Error('signed presentation did not verify');
}
if (inventory.artifact_type !== 'cred.vault_inventory') {
  throw new Error(`unexpected inventory artifact_type: ${inventory.artifact_type}`);
}
if (inventory.total_records !== 1) {
  throw new Error(`unexpected inventory total_records: ${inventory.total_records}`);
}
if (inventory.total_grants !== 1) {
  throw new Error(`unexpected inventory total_grants: ${inventory.total_grants}`);
}
if (inventory.total_grant_approvals !== 1) {
  throw new Error(`unexpected inventory total_grant_approvals: ${inventory.total_grant_approvals}`);
}
if (inventory.total_presentations !== 1) {
  throw new Error(`unexpected inventory total_presentations: ${inventory.total_presentations}`);
}
if (inventory.local_encrypted?.present !== 1 || inventory.local_encrypted?.missing !== 0) {
  throw new Error('inventory did not report the encrypted blob as present');
}
if (inventory.disclosure_modes?.reference !== 1) {
  throw new Error('inventory did not report one reference disclosure');
}
if (inventory.grant_decisions?.approved !== 1) {
  throw new Error('inventory did not report one approved grant decision');
}
const holding = inventory.holdings?.[0];
if (holding?.record_id !== record.record_id) {
  throw new Error(`unexpected inventory holding record_id: ${holding?.record_id}`);
}
if (holding.local_artifact?.status !== 'local_encrypted_present') {
  throw new Error(`unexpected local artifact status: ${holding.local_artifact?.status}`);
}
if (holding.category !== 'witness') {
  throw new Error(`unexpected category: ${holding.category}`);
}
const inventoryGrant = inventory.grants?.[0];
if (inventoryGrant?.grant_id !== grant.grant_id || inventoryGrant?.app_id !== grant.app_id) {
  throw new Error('inventory did not include imported grant metadata');
}
const inventoryApproval = inventory.grant_approvals?.[0];
if (inventoryApproval?.approval_id !== grantApproval.approval_id) {
  throw new Error('inventory did not include the grant approval record');
}
const audit = inventory.presentations?.[0];
if (audit?.presentation_id !== presentation.presentation_id) {
  throw new Error(`unexpected audit presentation_id: ${audit?.presentation_id}`);
}
if (audit?.presentation_hash !== verify.artifact_hash) {
  throw new Error('audit presentation hash does not match verified presentation hash');
}
if (audit?.approval_id !== grantApproval.approval_id) {
  throw new Error('audit did not retain the grant approval id');
}
if (audit?.artifacts?.[0]?.record_id !== record.record_id) {
  throw new Error('audit did not retain referenced record id');
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

console.log('Cred encrypted vault and audit smoke passed.');
