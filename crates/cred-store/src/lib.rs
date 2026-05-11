use cred_core::CredArtifactRecord;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

const RECORDS_FILE: &str = "records.jsonl";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid Cred record: {0}")]
    Cred(#[from] cred_core::CredError),
    #[error("invalid JSON record at line {line}: {source}")]
    Json {
        line: usize,
        source: serde_json::Error,
    },
    #[error("failed to encode record JSON: {0}")]
    Encode(#[source] serde_json::Error),
    #[error("record already exists: {0}")]
    DuplicateRecord(String),
    #[error("HOME is not set; pass --store")]
    MissingHome,
}

#[derive(Debug, Clone)]
pub struct RecordStore {
    root: PathBuf,
}

impl RecordStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn default_root() -> Result<PathBuf, StoreError> {
        if let Some(path) = env::var_os("CRED_STORE_DIR") {
            return Ok(PathBuf::from(path));
        }

        let home = env::var_os("HOME").ok_or(StoreError::MissingHome)?;
        Ok(PathBuf::from(home).join(".local/share/cred"))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn append_record(&self, record: &CredArtifactRecord) -> Result<(), StoreError> {
        record.validate()?;
        if self.get_record(&record.record_id)?.is_some() {
            return Err(StoreError::DuplicateRecord(record.record_id.clone()));
        }

        fs::create_dir_all(&self.root)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.records_path())?;
        serde_json::to_writer(&mut file, record).map_err(StoreError::Encode)?;
        file.write_all(b"\n")?;
        Ok(())
    }

    pub fn list_records(&self) -> Result<Vec<CredArtifactRecord>, StoreError> {
        let path = self.records_path();
        if !path.exists() {
            return Ok(Vec::new());
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut records = Vec::new();

        for (index, line) in reader.lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let record: CredArtifactRecord =
                serde_json::from_str(&line).map_err(|source| StoreError::Json {
                    line: index + 1,
                    source,
                })?;
            record.validate()?;
            records.push(record);
        }

        Ok(records)
    }

    pub fn get_record(&self, record_id: &str) -> Result<Option<CredArtifactRecord>, StoreError> {
        Ok(self
            .list_records()?
            .into_iter()
            .find(|record| record.record_id == record_id))
    }

    fn records_path(&self) -> PathBuf {
        self.root.join(RECORDS_FILE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cred_core::artifact_record;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn appends_lists_and_gets_records() {
        let root = temp_store_root("append-list-get");
        let store = RecordStore::new(&root);
        let record = sample_record("record-1");

        store.append_record(&record).unwrap();

        let records = store.list_records().unwrap();
        assert_eq!(records, vec![record.clone()]);
        assert_eq!(store.get_record("record-1").unwrap(), Some(record));
        assert_eq!(store.get_record("missing").unwrap(), None);

        cleanup(root);
    }

    #[test]
    fn rejects_duplicate_record_ids() {
        let root = temp_store_root("duplicates");
        let store = RecordStore::new(&root);
        let record = sample_record("record-1");

        store.append_record(&record).unwrap();
        let err = store.append_record(&record).unwrap_err();

        assert!(matches!(err, StoreError::DuplicateRecord(id) if id == "record-1"));

        cleanup(root);
    }

    #[test]
    fn reports_invalid_json_lines() {
        let root = temp_store_root("invalid-json");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(RECORDS_FILE), "{not-json}\n").unwrap();

        let err = RecordStore::new(&root).list_records().unwrap_err();

        assert!(matches!(err, StoreError::Json { line: 1, .. }));

        cleanup(root);
    }

    fn sample_record(record_id: &str) -> CredArtifactRecord {
        artifact_record(
            record_id.to_owned(),
            "cred:local:test".to_owned(),
            "cred.presentation".to_owned(),
            "1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
            "selective".to_owned(),
            "local_encrypted".to_owned(),
            Some("app:test".to_owned()),
            1,
            Some(vec!["test".to_owned()]),
        )
    }

    fn temp_store_root(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        env::temp_dir().join(format!("cred-store-{name}-{}-{nanos}", std::process::id()))
    }

    fn cleanup(root: PathBuf) {
        let _ = fs::remove_dir_all(root);
    }
}
