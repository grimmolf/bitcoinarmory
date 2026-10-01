//! Wallet files on disk: the main file, its `_backup` twin and Armory's update flag files
//! (spec 01 §10).
//!
//! Armory updated both files in place, guarded by empty flag files. This implementation keeps
//! the same file names and flag protocol, so Armory 0.93 still recovers correctly from an
//! interrupted write, but replaces each file atomically (temp file, fsync, rename, fsync dir).

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::legacy::{FILE_ID, LegacyWallet};
use crate::{Error, Result};

/// `getSuffixedPath`: `armory_ID_.wallet` + `backup` -> `armory_ID_backup.wallet`.
pub fn suffixed_path(path: &Path, suffix: &str) -> PathBuf {
    let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let ext = path.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
    let name =
        if stem.ends_with('_') { format!("{stem}{suffix}{ext}") } else { format!("{stem}_{suffix}{ext}") };
    path.with_file_name(name)
}

#[derive(Debug, Clone)]
pub struct WalletPaths {
    pub main: PathBuf,
    pub backup: PathBuf,
    pub main_flag: PathBuf,
    pub backup_flag: PathBuf,
}

impl WalletPaths {
    pub fn new(main: &Path) -> Self {
        Self {
            main: main.to_path_buf(),
            backup: suffixed_path(main, "backup"),
            main_flag: suffixed_path(main, "update_unsuccessful"),
            backup_flag: suffixed_path(main, "backup_unsuccessful"),
        }
    }
}

fn touch(p: &Path) -> Result<()> {
    let f = OpenOptions::new().create(true).truncate(false).write(true).open(p)?;
    f.sync_all()?;
    Ok(())
}

fn remove_if_exists(p: &Path) -> Result<()> {
    match fs::remove_file(p) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

fn sync_dir(p: &Path) -> Result<()> {
    if let Some(dir) = p.parent() {
        let dir = if dir.as_os_str().is_empty() { Path::new(".") } else { dir };
        File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Write `data` to `path` atomically with mode 0600.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    // Not a `.wallet` name, so a leftover temp file is never discovered as a wallet.
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    {
        let mut opts = OpenOptions::new();
        opts.create(true).truncate(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    sync_dir(path)
}

fn copy_atomic(from: &Path, to: &Path) -> Result<()> {
    atomic_write(to, &fs::read(from)?)
}

/// Refuse wallet files that other users can read (issue #281).
pub fn check_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(Error::InsecurePermissions { path: path.to_path_buf(), mode });
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// What the consistency check did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recovery {
    None,
    CreatedBackup,
    RestoredMainFromBackup,
    RefreshedBackupFromMain,
}

/// `doWalletFileConsistencyCheck` (spec 01 §10.3).
pub fn consistency_check(paths: &WalletPaths) -> Result<Recovery> {
    if !paths.backup.exists() {
        touch(&paths.backup_flag)?;
        copy_atomic(&paths.main, &paths.backup)?;
        remove_if_exists(&paths.backup_flag)?;
        return Ok(Recovery::CreatedBackup);
    }
    let main_flag = paths.main_flag.exists();
    let backup_flag = paths.backup_flag.exists();
    let r = if main_flag && backup_flag {
        copy_atomic(&paths.main, &paths.backup)?;
        Recovery::RefreshedBackupFromMain
    } else if main_flag {
        copy_atomic(&paths.backup, &paths.main)?;
        Recovery::RestoredMainFromBackup
    } else if backup_flag {
        copy_atomic(&paths.main, &paths.backup)?;
        Recovery::RefreshedBackupFromMain
    } else {
        Recovery::None
    };
    remove_if_exists(&paths.main_flag)?;
    remove_if_exists(&paths.backup_flag)?;
    Ok(r)
}

/// An open wallet file.
#[derive(Debug)]
pub struct WalletFile {
    pub paths: WalletPaths,
    pub wallet: LegacyWallet,
    pub recovery: Recovery,
}

impl WalletFile {
    /// Open read-write: runs the consistency check and the permission check.
    pub fn open(path: &Path) -> Result<Self> {
        let paths = WalletPaths::new(path);
        check_permissions(&paths.main)?;
        let recovery = consistency_check(&paths)?;
        let wallet = LegacyWallet::parse(&fs::read(&paths.main)?)?;
        Ok(Self { paths, wallet, recovery })
    }

    /// Open without touching any file (for inspection, e.g. on read-only media).
    pub fn open_read_only(path: &Path) -> Result<Self> {
        let paths = WalletPaths::new(path);
        let wallet = LegacyWallet::parse(&fs::read(&paths.main)?)?;
        Ok(Self { paths, wallet, recovery: Recovery::None })
    }

    /// Create a new wallet file (refuses to overwrite).
    pub fn create(path: &Path, wallet: LegacyWallet) -> Result<Self> {
        if path.exists() {
            return Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                path.display().to_string(),
            )));
        }
        let paths = WalletPaths::new(path);
        let mut f = Self { paths, wallet, recovery: Recovery::None };
        f.save()?;
        Ok(f)
    }

    /// `walletFileSafeUpdate`, with whole-file atomic replacement of each copy.
    ///
    /// Armory needed the main-file flag because it appended in place; with atomic renames the
    /// main file is always either the old or the new version, so only the backup flag is used.
    /// After a crash at any point the recovery converges on the main file (a lone backup flag
    /// means "copy main to backup", in this implementation and in Armory 0.93 alike).
    pub fn save(&mut self) -> Result<()> {
        let bytes = self.wallet.serialize();
        if self.paths.main.exists() {
            consistency_check(&self.paths)?;
        }
        touch(&self.paths.backup_flag)?;
        atomic_write(&self.paths.main, &bytes)?;
        atomic_write(&self.paths.backup, &bytes)?;
        remove_if_exists(&self.paths.backup_flag)?;
        self.wallet.repaired = false;
        Ok(())
    }
}

/// `readWalletFiles` discovery: `*.wallet` files with the Armory magic, excluding backups and
/// flag files.
pub fn discover(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for e in fs::read_dir(dir)? {
        let p = e?.path();
        let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if !name.ends_with(".wallet")
            || name.ends_with("backup.wallet")
            || name.ends_with("unsuccessful.wallet")
        {
            continue;
        }
        let mut head = [0u8; 8];
        if let Ok(mut f) = File::open(&p) {
            use std::io::Read;
            if f.read_exact(&mut head).is_ok() && head == FILE_ID {
                out.push(p);
            }
        }
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffixes() {
        let p = Path::new("/w/armory_ID_.wallet");
        assert_eq!(suffixed_path(p, "backup"), Path::new("/w/armory_ID_backup.wallet"));
        assert_eq!(
            suffixed_path(p, "update_unsuccessful"),
            Path::new("/w/armory_ID_update_unsuccessful.wallet")
        );
        let w = Path::new("/w/x_WatchOnly.wallet");
        assert_eq!(suffixed_path(w, "backup"), Path::new("/w/x_WatchOnly_backup.wallet"));
    }
}
