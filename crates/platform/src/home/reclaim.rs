use std::fs::{self, Metadata, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, fchown};
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct Target {
    pub path: PathBuf,
    pub dev: u64,
    pub ino: u64,
}

pub fn can_reclaim(home: &Path, uid: u32) -> bool {
    if home.as_os_str().is_empty() {
        return false;
    }
    fs::symlink_metadata(home).is_ok_and(|meta| meta.is_dir() && meta.uid() == uid)
}

/// A hard link is skipped so it cannot smuggle in an inode owned elsewhere.
pub fn should_reclaim_entry(meta: &Metadata, uid: u32) -> bool {
    if meta.file_type().is_symlink() || meta.uid() == uid {
        return false;
    }
    meta.is_dir() || meta.nlink() <= 1
}

pub fn collect_targets(home: &Path, uid: u32) -> Vec<Target> {
    if !can_reclaim(home, uid) {
        return Vec::new();
    }
    let mut targets = Vec::new();
    let mut pending = vec![home.to_path_buf()];
    while let Some(path) = pending.pop() {
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if should_reclaim_entry(&meta, uid) {
            targets.push(Target {
                path: path.clone(),
                dev: meta.dev(),
                ino: meta.ino(),
            });
        }
        if meta.is_dir()
            && let Ok(children) = fs::read_dir(&path)
        {
            pending.extend(children.flatten().map(|child| child.path()));
        }
    }
    targets
}

/// The inode seen when the target was collected must be the one opened, or the
/// path was swapped in between and nothing is changed.
pub fn reclaim_entry(target: &Target, uid: u32, gid: u32) -> io::Result<bool> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&target.path)?;
    let meta = file.metadata()?;
    if meta.dev() != target.dev || meta.ino() != target.ino {
        return Ok(false);
    }
    let reclaimable = meta.is_dir() || (meta.is_file() && meta.nlink() <= 1);
    if !reclaimable || meta.uid() == uid {
        return Ok(false);
    }
    fchown(&file, Some(uid), Some(gid))?;
    Ok(true)
}

pub fn reclaim_home(home: &Path, uid: u32, gid: u32) -> usize {
    let targets = collect_targets(home, uid);
    let mut reclaimed = 0;
    for target in &targets {
        match reclaim_entry(target, uid, gid) {
            Ok(true) => reclaimed += 1,
            Ok(false) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => tracing::warn!("reclaim {}: {err}", target.path.display()),
        }
    }
    if !targets.is_empty() {
        tracing::info!(
            "reclaimed {reclaimed} of {} elevated entries",
            targets.len()
        );
    }
    reclaimed
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    fn ids() -> (u32, u32) {
        let meta = fs::metadata(tempfile::tempdir().unwrap().path()).unwrap();
        (meta.uid(), meta.gid())
    }

    fn target_for(path: &Path) -> Target {
        let meta = fs::symlink_metadata(path).unwrap();
        Target {
            path: path.to_path_buf(),
            dev: meta.dev(),
            ino: meta.ino(),
        }
    }

    #[test]
    fn only_a_directory_owned_by_the_caller_can_be_reclaimed() {
        let home = tempfile::tempdir().unwrap();
        let (uid, _) = ids();
        assert!(can_reclaim(home.path(), uid));
        assert!(!can_reclaim(home.path(), uid + 1));
        assert!(!can_reclaim(Path::new(""), uid));
        assert!(!can_reclaim(&home.path().join("missing"), uid));

        let file = home.path().join("config.yaml");
        fs::write(&file, "mixed-port: 7890\n").unwrap();
        assert!(!can_reclaim(&file, uid));

        let link = home.path().join("link");
        symlink(home.path(), &link).unwrap();
        assert!(!can_reclaim(&link, uid));
    }

    #[test]
    fn owned_hard_linked_and_symlinked_entries_are_skipped() {
        let home = tempfile::tempdir().unwrap();
        let (uid, _) = ids();
        let foreign = uid + 1;
        let file = home.path().join("provider");
        fs::write(&file, "proxies: []\n").unwrap();

        let meta = fs::symlink_metadata(&file).unwrap();
        assert!(should_reclaim_entry(&meta, foreign));
        assert!(!should_reclaim_entry(&meta, uid));

        let hard = home.path().join("hardlink");
        fs::hard_link(&file, &hard).unwrap();
        assert!(!should_reclaim_entry(
            &fs::symlink_metadata(&hard).unwrap(),
            foreign
        ));

        let soft = home.path().join("symlink");
        symlink(&file, &soft).unwrap();
        assert!(!should_reclaim_entry(
            &fs::symlink_metadata(&soft).unwrap(),
            foreign
        ));

        let dir = fs::symlink_metadata(home.path()).unwrap();
        assert!(should_reclaim_entry(&dir, foreign));
    }

    #[test]
    fn the_walk_does_not_follow_symlinks_out_of_the_home_directory() {
        let home = tempfile::tempdir().unwrap();
        let (uid, _) = ids();
        let providers = home.path().join("profiles/providers/1/proxies");
        fs::create_dir_all(&providers).unwrap();
        fs::write(providers.join("abc"), "proxies: []\n").unwrap();
        assert!(collect_targets(home.path(), uid).is_empty());
        assert!(collect_targets(home.path(), uid + 1).is_empty());

        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret"), "secret").unwrap();
        symlink(outside.path(), home.path().join("escape")).unwrap();
        let walked = collect_targets(home.path(), uid);
        assert!(walked.iter().all(|t| !t.path.starts_with(outside.path())));
        assert!(
            walked
                .iter()
                .all(|t| t.path != home.path().join("escape/secret"))
        );
    }

    #[test]
    fn the_inode_is_verified_before_the_ownership_changes() {
        let home = tempfile::tempdir().unwrap();
        let (uid, gid) = ids();
        let foreign = uid + 1;
        let file = home.path().join("provider");
        fs::write(&file, "proxies: []\n").unwrap();
        assert!(!reclaim_entry(&target_for(&file), uid, gid).unwrap());

        let hard = home.path().join("hardlink");
        fs::hard_link(&file, &hard).unwrap();
        assert!(!reclaim_entry(&target_for(&hard), foreign, gid).unwrap());

        let soft = home.path().join("symlink");
        symlink(&file, &soft).unwrap();
        let err = reclaim_entry(&target_for(&soft), foreign, gid).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ELOOP));

        let missing = Target {
            path: home.path().join("missing"),
            dev: 0,
            ino: 0,
        };
        let err = reclaim_entry(&missing, foreign, gid).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);

        let plain = home.path().join("plain");
        fs::write(&plain, "proxies: []\n").unwrap();
        if uid != 0 {
            assert!(reclaim_entry(&target_for(&plain), foreign, gid).is_err());
        }
    }

    #[test]
    fn a_path_swapped_through_an_intermediate_component_is_refused() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let (uid, gid) = ids();
        let profiles = home.path().join("profiles");
        fs::create_dir(&profiles).unwrap();
        let entry = profiles.join("provider");
        fs::write(&entry, "proxies: []\n").unwrap();
        let target = target_for(&entry);

        fs::write(outside.path().join("provider"), "secret").unwrap();
        fs::rename(&profiles, home.path().join("moved")).unwrap();
        symlink(outside.path(), &profiles).unwrap();

        assert!(!reclaim_entry(&target, uid + 1, gid).unwrap());
    }

    #[test]
    fn a_fifo_is_skipped_without_blocking() {
        let home = tempfile::tempdir().unwrap();
        let (uid, gid) = ids();
        let fifo = home.path().join("pipe");
        let path = std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(fifo.as_os_str()))
            .unwrap();
        // SAFETY: `path` is NUL-terminated.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert!(!reclaim_entry(&target_for(&fifo), uid + 1, gid).unwrap());
    }
}
