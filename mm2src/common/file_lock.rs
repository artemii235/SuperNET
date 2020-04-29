use crate::now_ms;
use std::path::Path;

pub struct FileLock<'a> {
    /// Filesystem path of the lock file.
    lock_path: &'a dyn AsRef<Path>,
    /// The time in seconds after which an outdated lock file can be removed.
    ttl_sec: u64,
}

/// Records timestamp to a file contents.
fn touch(path: &dyn AsRef<Path>, timestamp: u64) -> Result<(), String> {
    std::fs::write(path.as_ref(), timestamp.to_string()).map_err(|e| ERRL!("{:?}", e))
}

/// Attempts to read timestamp recorded to a file
fn read_timestamp(path: &dyn AsRef<Path>) -> Result<u64, String> {
    match std::fs::read_to_string(path) {
        Ok(content) => content.parse().map_err(|e| ERRL!("{:?}", e)),
        Err(e) => ERR!("{:?}", e)
    }
}

impl<'a> FileLock<'a> {
    pub fn lock(lock_path: &'a dyn AsRef<Path>, ttl_sec: u64) -> Result<Option<FileLock>, String> {
        match std::fs::OpenOptions::new().write(true).create_new(true).open(lock_path.as_ref()) {
            Ok(_) => {
                let file_lock = FileLock { lock_path, ttl_sec };
                try_s!(file_lock.touch());
                Ok(Some(file_lock))
            },
            Err(ref ie) if ie.kind() == std::io::ErrorKind::AlreadyExists => {
                // See if the existing lock is old enough to be discarded.
                let lm = match read_timestamp(lock_path) {
                    Ok(lm) => lm,
                    Err(ie) => return ERR!("Error checking {:?}: {}", lock_path.as_ref(), ie)
                };
                if now_ms() / 1000 - lm > ttl_sec {
                    let file_lock = FileLock { lock_path, ttl_sec };
                    try_s!(file_lock.touch());
                    return Ok(Some(file_lock));
                }
                Ok(None)
            },
            Err(ie) => ERR!("Error creating {:?}: {}", lock_path.as_ref(), ie)
        }
    }

    pub fn touch(&self) -> Result<(), String> {
        touch(self.lock_path, now_ms() / 1000)
    }
}

impl<'a> Drop for FileLock<'a> {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.lock_path.as_ref());
    }
}

#[cfg(test)]
mod file_lock_tests {
    use std::{
        thread::sleep,
        time::Duration,
    };
    use super::*;

    #[test]
    fn test_file_lock_should_create_file_and_record_timestamp_and_then_delete_on_drop() {
        let now = now_ms() / 1000;
        let path = Path::new("test1.lock");
        let lock = FileLock::lock(&path, 1000).unwrap().unwrap();
        assert!(path.exists());
        let timestamp = read_timestamp(&path).unwrap();
        assert!(timestamp >= now);
        drop(lock);
        assert!(!path.exists());
    }

    #[test]
    fn test_file_lock_should_return_none_if_lock_acquired() {
        let path = Path::new("test2.lock");
        let _lock = FileLock::lock(&path, 1000).unwrap().unwrap();
        let new_lock = FileLock::lock(&path, 1000).unwrap();
        assert!(new_lock.is_none());
    }

    #[test]
    fn test_file_lock_should_acquire_if_ttl_expired_and_update_timestamp() {
        let path = Path::new("test3.lock");
        let _lock = FileLock::lock(&path, 1).unwrap().unwrap();
        sleep(Duration::from_secs(2));
        let old_timestamp = read_timestamp(&path).unwrap();
        let _new_lock = FileLock::lock(&path, 1).unwrap().unwrap();
        let new_timestamp = read_timestamp(&path).unwrap();
        assert!(new_timestamp > old_timestamp);
    }
}
