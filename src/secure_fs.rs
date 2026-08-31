use std::{io, path::Path};

pub(crate) const MAX_CONFIG_FILE_BYTES: usize = 64 * 1024;
pub(crate) const MAX_KEY_FILE_BYTES: usize = 16 * 1024;

#[derive(Debug, thiserror::Error)]
pub(crate) enum SecureFsError {
    #[error("secure storage is unsupported")]
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    Unsupported,
    #[error("secure path was not found")]
    NotFound,
    #[error("secure destination already exists")]
    AlreadyExists,
    #[error("secure directory is not private")]
    InsecureDirectory,
    #[error("secure file is not private")]
    InsecureFile,
    #[error("secure file exceeds size limit")]
    TooLarge,
    #[error("secure path is invalid")]
    InvalidPath,
    #[error("secure storage operation failed")]
    Io(#[source] io::Error),
}

impl SecureFsError {
    pub(crate) fn into_io(self) -> io::Error {
        let kind = match self {
            Self::Unsupported => io::ErrorKind::Unsupported,
            Self::NotFound => io::ErrorKind::NotFound,
            Self::AlreadyExists => io::ErrorKind::AlreadyExists,
            Self::InsecureDirectory | Self::InsecureFile => io::ErrorKind::PermissionDenied,
            Self::TooLarge => io::ErrorKind::InvalidData,
            Self::InvalidPath => io::ErrorKind::InvalidInput,
            Self::Io(error) => return error,
        };
        io::Error::new(kind, self)
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::{
        ffi::{OsStr, OsString},
        fs::File,
        io::{Read, Write},
        os::fd::{AsRawFd, OwnedFd},
        path::{Component, Path},
    };

    use rustix::fs::{
        AtFlags, Mode, OFlags, RenameFlags, fsync, mkdirat, open, openat, renameat_with, unlinkat,
    };

    use super::SecureFsError;

    const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);
    const FILE_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);
    const PRIVATE_DIR: Mode = Mode::from_raw_mode(0o700);
    const PRIVATE_FILE: Mode = Mode::from_raw_mode(0o600);
    const PRIVATE_FILE_MODE: u32 = 0o600;
    const PRIVATE_DIR_MODE: u32 = 0o700;
    const PERMISSION_BITS: u32 = 0o7777;
    const TEMP_PREFIX: &str = ".mg-contacts.";
    const TEMP_SUFFIX: &str = ".tmp";

    #[derive(Debug)]
    pub(super) struct ParentDir {
        fd: OwnedFd,
        name: OsString,
    }

    impl ParentDir {
        fn open(path: &Path, create: bool) -> Result<Self, SecureFsError> {
            if !path.is_absolute() {
                return Err(SecureFsError::InvalidPath);
            }
            let name = path
                .file_name()
                .ok_or(SecureFsError::InvalidPath)?
                .to_os_string();
            let parent = path.parent().ok_or(SecureFsError::InvalidPath)?;
            let mut current = open("/", DIRECTORY_FLAGS, Mode::empty()).map_err(map_io)?;
            for component in parent.components() {
                let Component::Normal(component) = component else {
                    if matches!(component, Component::RootDir) {
                        continue;
                    }
                    return Err(SecureFsError::InvalidPath);
                };
                current = open_child_dir(&current, component, create)?;
            }
            Ok(Self { fd: current, name })
        }

        fn create_private_file(&self, name: &OsStr) -> Result<File, SecureFsError> {
            let flags =
                OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            openat(&self.fd, name, flags, PRIVATE_FILE)
                .map(File::from)
                .map_err(map_io)
        }

        fn open_private_file(&self) -> Result<File, SecureFsError> {
            let fd = openat(&self.fd, &self.name, FILE_FLAGS, Mode::empty())
                .map_err(map_file_open_error)?;
            let stat = rustix::fs::fstat(&fd).map_err(map_io)?;
            validate_private_file_metadata(
                stat.st_mode,
                stat.st_nlink,
                stat.st_uid,
                rustix::process::geteuid().as_raw(),
            )?;
            Ok(File::from(fd))
        }

        fn sync(&self) -> Result<(), SecureFsError> {
            fsync(&self.fd).map_err(map_io)
        }
    }

    fn map_io(error: rustix::io::Errno) -> SecureFsError {
        match error {
            rustix::io::Errno::NOENT => SecureFsError::NotFound,
            rustix::io::Errno::EXIST => SecureFsError::AlreadyExists,
            rustix::io::Errno::INVAL | rustix::io::Errno::NAMETOOLONG => SecureFsError::InvalidPath,
            _ => SecureFsError::Io(error.into()),
        }
    }

    fn map_directory_open_error(error: rustix::io::Errno) -> SecureFsError {
        match error {
            rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => SecureFsError::InsecureDirectory,
            _ => map_io(error),
        }
    }

    fn map_file_open_error(error: rustix::io::Errno) -> SecureFsError {
        match error {
            rustix::io::Errno::LOOP | rustix::io::Errno::NOTDIR => SecureFsError::InsecureFile,
            _ => map_io(error),
        }
    }

    fn validate_private_file_metadata(
        mode: u32,
        link_count: u64,
        owner: u32,
        expected_owner: u32,
    ) -> Result<(), SecureFsError> {
        if !rustix::fs::FileType::from_raw_mode(mode).is_file()
            || link_count != 1
            || owner != expected_owner
            || mode & PERMISSION_BITS != PRIVATE_FILE_MODE
        {
            return Err(SecureFsError::InsecureFile);
        }
        Ok(())
    }

    fn validate_private_dir(fd: &OwnedFd) -> Result<(), SecureFsError> {
        let stat = rustix::fs::fstat(fd).map_err(map_io)?;
        if !rustix::fs::FileType::from_raw_mode(stat.st_mode).is_dir()
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_mode & PERMISSION_BITS != PRIVATE_DIR_MODE
        {
            return Err(SecureFsError::InsecureDirectory);
        }
        Ok(())
    }

    fn read_bounded(reader: impl Read, max_bytes: usize) -> Result<Vec<u8>, SecureFsError> {
        let mut bytes = Vec::with_capacity(max_bytes.min(8 * 1024));
        reader
            .take(max_bytes.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .map_err(SecureFsError::Io)?;
        if bytes.len() > max_bytes {
            return Err(SecureFsError::TooLarge);
        }
        Ok(bytes)
    }

    fn open_child_dir(
        parent: &OwnedFd,
        name: &OsStr,
        create: bool,
    ) -> Result<OwnedFd, SecureFsError> {
        match openat(parent, name, DIRECTORY_FLAGS, Mode::empty()) {
            Ok(fd) => Ok(fd),
            Err(error) if create && error == rustix::io::Errno::NOENT => {
                match mkdirat(parent, name, PRIVATE_DIR) {
                    Ok(()) => {}
                    Err(error) if error == rustix::io::Errno::EXIST => {}
                    Err(error) => return Err(map_io(error)),
                }
                openat(parent, name, DIRECTORY_FLAGS, Mode::empty())
                    .map_err(map_directory_open_error)
            }
            Err(error) => Err(map_directory_open_error(error)),
        }
    }

    pub(super) fn ensure_private_dir(path: &Path) -> Result<(), SecureFsError> {
        let parent = ParentDir::open(path, true)?;
        let fd = match openat(&parent.fd, &parent.name, DIRECTORY_FLAGS, Mode::empty()) {
            Ok(fd) => fd,
            Err(error) if error == rustix::io::Errno::NOENT => {
                match mkdirat(&parent.fd, &parent.name, PRIVATE_DIR) {
                    Ok(()) => {}
                    Err(error) if error == rustix::io::Errno::EXIST => {}
                    Err(error) => return Err(map_io(error)),
                }
                openat(&parent.fd, &parent.name, DIRECTORY_FLAGS, Mode::empty())
                    .map_err(map_directory_open_error)?
            }
            Err(error) => return Err(map_directory_open_error(error)),
        };
        validate_private_dir(&fd)?;
        parent.sync()
    }

    pub(super) fn read_private_file(
        path: &Path,
        max_bytes: usize,
    ) -> Result<Vec<u8>, SecureFsError> {
        let parent = ParentDir::open(path, false)?;
        let file = parent.open_private_file()?;
        if file.metadata().map_err(SecureFsError::Io)?.len() > max_bytes as u64 {
            return Err(SecureFsError::TooLarge);
        }
        read_bounded(file, max_bytes)
    }

    pub(super) fn read_optional_private_file(
        path: &Path,
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, SecureFsError> {
        match read_private_file(path, max_bytes) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(SecureFsError::NotFound) => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub(super) fn regular_file_exists(path: &Path) -> Result<bool, SecureFsError> {
        let parent = match ParentDir::open(path, false) {
            Ok(parent) => parent,
            Err(SecureFsError::NotFound) => return Ok(false),
            Err(error) => return Err(error),
        };
        validate_private_dir(&parent.fd)?;
        recover_orphan_temps(&parent)?;
        match parent.open_private_file() {
            Ok(_) => Ok(true),
            Err(SecureFsError::NotFound) => Ok(false),
            Err(error) => Err(error),
        }
    }

    fn orphan_pid(name: &str) -> Option<u32> {
        let body = name.strip_prefix(TEMP_PREFIX)?.strip_suffix(TEMP_SUFFIX)?;
        let (pid, random) = body.split_once('.')?;
        if random.is_empty() || !random.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        pid.parse().ok()
    }

    fn recover_orphan_temps(parent: &ParentDir) -> Result<(), SecureFsError> {
        let descriptor_path = format!("/proc/self/fd/{}", parent.fd.as_raw_fd());
        for entry in std::fs::read_dir(descriptor_path).map_err(SecureFsError::Io)? {
            let entry = entry.map_err(SecureFsError::Io)?;
            let name = entry.file_name();
            let Some(name_text) = name.to_str() else {
                continue;
            };
            let Some(pid) = orphan_pid(name_text) else {
                continue;
            };
            if Path::new("/proc").join(pid.to_string()).exists() {
                continue;
            }
            match unlinkat(&parent.fd, &name, AtFlags::empty()) {
                Ok(()) => {}
                Err(error) if error == rustix::io::Errno::NOENT => {}
                Err(error) => return Err(map_io(error)),
            }
        }
        Ok(())
    }

    fn install_new_file_with_hook(
        path: &Path,
        bytes: &[u8],
        after_publish: impl FnOnce() -> Result<(), SecureFsError>,
    ) -> Result<(), SecureFsError> {
        let parent = ParentDir::open(path, true)?;
        validate_private_dir(&parent.fd)?;
        recover_orphan_temps(&parent)?;
        let temp_name = OsString::from(format!(
            "{TEMP_PREFIX}{}.{}{TEMP_SUFFIX}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let before_publish = (|| {
            let mut file = parent.create_private_file(&temp_name)?;
            file.write_all(bytes).map_err(SecureFsError::Io)?;
            file.sync_all().map_err(SecureFsError::Io)?;
            renameat_with(
                &parent.fd,
                &temp_name,
                &parent.fd,
                &parent.name,
                RenameFlags::NOREPLACE,
            )
            .map_err(map_io)
        })();
        if let Err(error) = before_publish {
            let _ = unlinkat(&parent.fd, &temp_name, AtFlags::empty());
            return Err(error);
        }
        after_publish()?;
        parent.sync()
    }

    pub(super) fn install_new_file(path: &Path, bytes: &[u8]) -> Result<(), SecureFsError> {
        install_new_file_with_hook(path, bytes, || Ok(()))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{fs, io, os::unix::fs::PermissionsExt};

        fn private_tempdir() -> tempfile::TempDir {
            let root = tempfile::tempdir().unwrap();
            fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
            root
        }

        #[test]
        fn held_parent_descriptor_cannot_be_redirected_by_symlink_swap() {
            let root = private_tempdir();
            let safe = root.path().join("safe");
            let attacker = root.path().join("attacker");
            fs::create_dir(&safe).unwrap();
            fs::create_dir(&attacker).unwrap();
            let parent = ParentDir::open(&safe.join("value"), false).unwrap();
            let moved = root.path().join("moved");
            fs::rename(&safe, &moved).unwrap();
            std::os::unix::fs::symlink(&attacker, &safe).unwrap();
            let mut file = parent.create_private_file(OsStr::new("value")).unwrap();
            file.write_all(b"safe").unwrap();
            file.sync_all().unwrap();
            assert_eq!(fs::read(moved.join("value")).unwrap(), b"safe");
            assert!(!attacker.join("value").exists());
        }

        #[test]
        fn file_limits_and_growth_are_enforced() {
            let root = private_tempdir();
            let path = root.path().join("sized");
            fs::write(&path, vec![0_u8; super::super::MAX_KEY_FILE_BYTES + 1]).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(matches!(
                read_private_file(&path, super::super::MAX_KEY_FILE_BYTES),
                Err(SecureFsError::TooLarge)
            ));
            assert_eq!(
                read_private_file(&path, super::super::MAX_CONFIG_FILE_BYTES)
                    .unwrap()
                    .len(),
                super::super::MAX_KEY_FILE_BYTES + 1
            );
            assert!(matches!(
                read_bounded(io::Cursor::new(vec![0_u8; 33]), 32),
                Err(SecureFsError::TooLarge)
            ));
        }

        #[test]
        fn insecure_files_are_typed_and_not_repaired() {
            let root = private_tempdir();
            let path = root.path().join("key");
            fs::write(&path, b"secret").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(matches!(
                regular_file_exists(&path),
                Err(SecureFsError::InsecureFile)
            ));
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o644
            );
            assert!(matches!(
                validate_private_file_metadata(0o100_600, 1, 1000, 1001),
                Err(SecureFsError::InsecureFile)
            ));
        }

        #[test]
        fn hard_linked_file_is_rejected() {
            let root = private_tempdir();
            let path = root.path().join("key");
            fs::write(&path, b"secret").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            fs::hard_link(&path, root.path().join("alias")).unwrap();
            assert!(matches!(
                read_private_file(&path, 32),
                Err(SecureFsError::InsecureFile)
            ));
        }

        #[test]
        fn insecure_directory_is_rejected_without_permission_repair() {
            let root = private_tempdir();
            let path = root.path().join("shared");
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(matches!(
                ensure_private_dir(&path),
                Err(SecureFsError::InsecureDirectory)
            ));
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }

        #[test]
        fn no_replace_install_is_atomic_and_recovers_orphans() {
            let root = private_tempdir();
            let path = root.path().join("key");
            fs::write(&path, b"original").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(matches!(
                install_new_file(&path, b"replacement"),
                Err(SecureFsError::AlreadyExists)
            ));
            assert_eq!(fs::read(&path).unwrap(), b"original");

            let orphan = root.path().join(".mg-contacts.4294967295.7.tmp");
            fs::write(&orphan, b"orphan").unwrap();
            fs::set_permissions(&orphan, fs::Permissions::from_mode(0o600)).unwrap();
            fs::remove_file(&path).unwrap();
            assert!(!regular_file_exists(&path).unwrap());
            assert!(!orphan.exists());
            install_new_file(&path, b"new").unwrap();
            assert_eq!(fs::read(&path).unwrap(), b"new");
        }

        #[test]
        fn failure_after_publication_leaves_readable_single_link_destination() {
            use std::os::unix::fs::MetadataExt;
            let root = private_tempdir();
            let path = root.path().join("key");
            let result = install_new_file_with_hook(&path, b"new", || {
                Err(SecureFsError::Io(io::Error::other("injected crash point")))
            });
            assert!(result.is_err());
            assert_eq!(read_private_file(&path, 32).unwrap(), b"new");
            assert_eq!(fs::metadata(&path).unwrap().nlink(), 1);
        }

        #[test]
        fn non_normal_and_relative_secure_paths_are_rejected() {
            let root = private_tempdir();
            for path in [
                Path::new("relative/key").to_path_buf(),
                root.path().join("a/../key"),
            ] {
                assert!(matches!(
                    ParentDir::open(&path, true),
                    Err(SecureFsError::InvalidPath)
                ));
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::SecureFsError;
    use std::path::Path;
    pub(super) fn ensure_private_dir(_: &Path) -> Result<(), SecureFsError> {
        Err(SecureFsError::Unsupported)
    }
    pub(super) fn read_private_file(_: &Path, _: usize) -> Result<Vec<u8>, SecureFsError> {
        Err(SecureFsError::Unsupported)
    }
    pub(super) fn read_optional_private_file(
        _: &Path,
        _: usize,
    ) -> Result<Option<Vec<u8>>, SecureFsError> {
        Err(SecureFsError::Unsupported)
    }
    pub(super) fn regular_file_exists(_: &Path) -> Result<bool, SecureFsError> {
        Err(SecureFsError::Unsupported)
    }
    pub(super) fn install_new_file(_: &Path, _: &[u8]) -> Result<(), SecureFsError> {
        Err(SecureFsError::Unsupported)
    }
}

pub(crate) fn ensure_private_dir(path: &Path) -> Result<(), SecureFsError> {
    platform::ensure_private_dir(path)
}
pub(crate) fn read_private_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, SecureFsError> {
    platform::read_private_file(path, max_bytes)
}
pub(crate) fn read_optional_private_file(
    path: &Path,
    max_bytes: usize,
) -> Result<Option<Vec<u8>>, SecureFsError> {
    platform::read_optional_private_file(path, max_bytes)
}
pub(crate) fn regular_file_exists(path: &Path) -> Result<bool, SecureFsError> {
    platform::regular_file_exists(path)
}
pub(crate) fn install_new_file(path: &Path, bytes: &[u8]) -> Result<(), SecureFsError> {
    platform::install_new_file(path, bytes)
}
