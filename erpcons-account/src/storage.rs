//! Shared PI directory: paths, atomic writes, device-signed files and `pi.lock` (lease.md §11).
use std::{
    fs::{self, File, OpenOptions},
    io::{ErrorKind, Read, Write},
    path::{Path, PathBuf},
};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::{Error, Product, jose};

const MAX_FILE: u64 = 64 << 10;

#[derive(Clone, Debug)]
pub(crate) struct Paths {
    dir: PathBuf,
}

impl Paths {
    pub(crate) fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
    pub(crate) fn session(&self) -> PathBuf {
        self.dir.join("session.json")
    }
    pub(crate) fn lease(&self, p: Product) -> PathBuf {
        self.dir.join(format!("lease-{}.json", p.id()))
    }
    pub(crate) fn catalog(&self, p: Product) -> PathBuf {
        self.dir.join(format!("catalog-{}.jws", p.id()))
    }
    fn lock(&self) -> PathBuf {
        self.dir.join("pi.lock")
    }

    /// Exclusive cross-process lock on `pi.lock`, released on drop.
    pub(crate) fn lock_exclusive(&self) -> Result<FileLock, Error> {
        fs::create_dir_all(&self.dir)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.lock())?;
        file.lock()?;
        Ok(FileLock { file })
    }
}

/// Windows `%APPDATA%\ERPCons\PI`, macOS `~/Library/Application Support/ERPCons/PI`,
/// Linux `$XDG_CONFIG_HOME/erpcons/pi` (default `~/.config/erpcons/pi`).
pub(crate) fn default_dir() -> Option<PathBuf> {
    let env = |k: &str| {
        std::env::var_os(k)
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    if cfg!(windows) {
        Some(env("APPDATA")?.join("ERPCons").join("PI"))
    } else if cfg!(target_os = "macos") {
        Some(env("HOME")?.join("Library/Application Support/ERPCons/PI"))
    } else {
        let config = env("XDG_CONFIG_HOME").or_else(|| Some(env("HOME")?.join(".config")))?;
        Some(config.join("erpcons").join("pi"))
    }
}

pub(crate) struct FileLock {
    file: File,
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

pub(crate) fn read(path: &Path) -> Result<Option<Vec<u8>>, Error> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut bytes = Vec::new();
    file.take(MAX_FILE + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_FILE {
        return Ok(None);
    }
    Ok(Some(bytes))
}

/// Temporary file, fsync, rename (as `write_json` in erpcons-update).
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let temporary = path.with_extension("writing");
    let mut file = File::create(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    if fs::rename(&temporary, path).is_err() {
        // A reader on Windows can briefly block the replace; retry once after removing.
        remove(path)?;
        fs::rename(&temporary, path)?;
    }
    Ok(())
}

pub(crate) fn remove(path: &Path) -> Result<(), Error> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

/// File body plus a detached Ed25519 signature over its exact bytes, on a second line, so a
/// single rename replaces both.
pub(crate) fn seal(body: &[u8], key: &SigningKey) -> Vec<u8> {
    let sig = jose::b64(&key.sign(body).to_bytes());
    let mut out = Vec::with_capacity(body.len() + sig.len() + 2);
    out.extend_from_slice(body);
    out.push(b'\n');
    out.extend_from_slice(sig.as_bytes());
    out.push(b'\n');
    out
}

pub(crate) fn unseal<'a>(file: &'a [u8], key: &VerifyingKey) -> Option<&'a [u8]> {
    let file = file.strip_suffix(b"\n")?;
    let split = file.iter().rposition(|b| *b == b'\n')?;
    let (body, sig) = (&file[..split], &file[split + 1..]);
    let sig = Signature::from_slice(&jose::unb64(std::str::from_utf8(sig).ok()?)?).ok()?;
    key.verify_strict(body, &sig).ok()?;
    Some(body)
}
