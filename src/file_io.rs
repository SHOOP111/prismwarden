//! Shared regular-file I/O. Ancestor-directory races still require a trusted snapshot.
use anyhow::{Result, ensure};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::Read;
use std::path::Path;

pub(crate) fn is_link(metadata: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_type().is_symlink() || metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

pub(crate) fn unchanged(before: &Metadata, after: &Metadata) -> bool {
    if !after.is_file()
        || is_link(after)
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.ctime() == after.ctime()
            && before.ctime_nsec() == after.ctime_nsec()
            && before.mode() == after.mode()
    }
    #[cfg(not(unix))]
    {
        before.created().ok() == after.created().ok()
            && before.permissions().readonly() == after.permissions().readonly()
    }
}

fn open_regular(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: open the reparse point, not its target.
        options.custom_flags(0x0020_0000);
    }
    options.open(path)
}

pub(crate) fn read_snapshot(
    path: &Path,
    expected: &Metadata,
) -> std::result::Result<Vec<u8>, &'static str> {
    let mut file = open_regular(path).map_err(|_| "read_error")?;
    let metadata = file.metadata().map_err(|_| "metadata_error")?;
    if !unchanged(expected, &metadata) {
        return Err("file_changed");
    }
    let mut bytes = Vec::with_capacity(expected.len() as usize);
    (&mut file)
        .take(expected.len() + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "read_error")?;
    let after = file.metadata().map_err(|_| "metadata_error")?;
    let entry = fs::symlink_metadata(path).map_err(|_| "file_changed")?;
    if bytes.len() as u64 != expected.len()
        || !unchanged(expected, &after)
        || !unchanged(expected, &entry)
    {
        return Err("file_changed");
    }
    Ok(bytes)
}

/// Explicit policy inputs must not block on FIFOs/devices or follow final links.
pub(crate) fn read_input(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| anyhow::anyhow!("cannot inspect input file"))?;
    ensure!(
        metadata.is_file() && !is_link(&metadata),
        "input must be a regular file, not a symlink or special file"
    );
    ensure!(metadata.len() <= limit, "input file exceeds size limit");
    read_snapshot(path, &metadata).map_err(|code| anyhow::anyhow!("cannot read input: {code}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_with_same_length_is_not_the_discovered_file() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("source");
        fs::write(&path, b"before").unwrap();
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert_eq!(read_snapshot(&path, &metadata).unwrap(), b"before");
        // Keep the old inode alive; do not rely on timestamp resolution or sleeps.
        fs::rename(&path, root.path().join("old-source")).unwrap();
        fs::write(&path, b"after!").unwrap();
        #[cfg(unix)]
        assert_eq!(read_snapshot(&path, &metadata).unwrap_err(), "file_changed");
    }

    #[test]
    fn changed_length_and_oversized_explicit_inputs_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("source");
        fs::write(&path, b"small").unwrap();
        let metadata = fs::symlink_metadata(&path).unwrap();
        fs::write(&path, b"larger content").unwrap();
        assert_eq!(read_snapshot(&path, &metadata).unwrap_err(), "file_changed");
        assert!(read_input(&path, 5).is_err());
        assert!(read_input(root.path(), 1024).is_err());
    }
}
