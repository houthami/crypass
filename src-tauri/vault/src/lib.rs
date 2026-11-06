//! The encrypted account store.
//!
//! The file holds an Argon2id configuration and an AES-256-GCM encrypted copy
//! of every account. The header is authenticated along with the contents, so
//! changing any part of the file makes it fail to open.
//!
//! Secrets are wiped from memory on drop where this crate controls them. This
//! is best effort: it can't reach copies made by the OS or the allocator.

pub mod generator;
pub mod matching;

use std::fmt;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const MIN_PASSWORD_CHARS: usize = 12;

const FORMAT: &str = "crypass-vault";
const VERSION: u32 = 1;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 12;
const BEFORE_RESTORE: &str = "before-restore";
const QUICK_UNLOCK: &str = "hello";

// Upper limits stop a tampered file from forcing a huge memory allocation.
const MAX_MEMORY_KIB: u32 = 2 * 1024 * 1024;
const MAX_ITERATIONS: u32 = 64;
const MAX_PARALLELISM: u32 = 16;

/// Cost of turning the master password into the encryption key.
#[derive(Clone, Copy)]
pub struct KdfSettings {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfSettings {
    /// 64 MiB, 3 passes, 4 lanes: the second recommended option in RFC 9106.
    fn default() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 4,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    AlreadyExists,
    PasswordTooShort,
    WrongPasswordOrTampered,
    Damaged(&'static str),
    InvalidAccount(&'static str),
    AccountNotFound,
    InvalidBackupDestination,
    BackupMismatch,
    SamePassword,
    QuickUnlockFailed,
    OldCopyRemains(PathBuf),
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AlreadyExists => write!(f, "A vault already exists."),
            Error::PasswordTooShort => write!(
                f,
                "The master password must have at least {MIN_PASSWORD_CHARS} characters."
            ),
            Error::WrongPasswordOrTampered => {
                write!(f, "Wrong master password, or the vault file was changed.")
            }
            Error::Damaged(reason) => write!(f, "The vault file can't be read: {reason}."),
            Error::InvalidAccount(reason) => write!(f, "{reason}"),
            Error::AccountNotFound => write!(f, "That account no longer exists."),
            Error::InvalidBackupDestination => {
                write!(f, "Choose a different location from the vault itself.")
            }
            Error::BackupMismatch => {
                write!(f, "The backup doesn't match the vault. Try another location.")
            }
            Error::SamePassword => write!(f, "Choose a different password from the current one."),
            Error::QuickUnlockFailed => {
                write!(f, "Windows Hello couldn't open the vault. Use your master password.")
            }
            Error::OldCopyRemains(path) => write!(
                f,
                "The password was changed, but an old copy couldn't be deleted. Delete it yourself: {}",
                path.display()
            ),
            Error::Io(error) => write!(f, "Couldn't access the vault file: {error}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(error)
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    pub id: u32,
    pub label: String,
    pub username: String,
    pub password: String,
    /// Sites and apps this account has been used with. Vaults made before this
    /// field existed load with an empty list.
    #[serde(default)]
    pub matches: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct Contents {
    next_id: u32,
    entries: Vec<Entry>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Kdf {
    algorithm: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct Header {
    format: String,
    version: u32,
    kdf: Kdf,
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    header: Header,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct QuickUnlockFile {
    nonce: String,
    ciphertext: String,
}

pub struct Vault {
    path: PathBuf,
    header: Header,
    key: Zeroizing<[u8; 32]>,
    contents: Contents,
}

impl Vault {
    pub fn create(path: &Path, password: &str) -> Result<Self, Error> {
        Self::create_with(path, password, KdfSettings::default())
    }

    pub fn create_with(path: &Path, password: &str, kdf: KdfSettings) -> Result<Self, Error> {
        if password.chars().count() < MIN_PASSWORD_CHARS {
            return Err(Error::PasswordTooShort);
        }
        if path.exists() {
            return Err(Error::AlreadyExists);
        }

        let mut salt = [0u8; SALT_BYTES];
        OsRng.fill_bytes(&mut salt);
        let header = Header {
            format: FORMAT.into(),
            version: VERSION,
            kdf: Kdf {
                algorithm: "argon2id".into(),
                memory_kib: kdf.memory_kib,
                iterations: kdf.iterations,
                parallelism: kdf.parallelism,
                salt: hex::encode(salt),
            },
        };

        let vault = Self {
            path: path.to_path_buf(),
            key: derive_key(password, &header.kdf)?,
            header,
            contents: Contents {
                next_id: 1,
                entries: Vec::new(),
            },
        };
        vault.write(&vault.contents)?;
        Ok(vault)
    }

    pub fn open(path: &Path, password: &str) -> Result<Self, Error> {
        Self::open_bytes(path, &fs::read(path)?, password)
    }

    fn open_bytes(path: &Path, bytes: &[u8], password: &str) -> Result<Self, Error> {
        let file = parse_file(bytes)?;
        let key = derive_key(password, &file.header.kdf)?;
        Self::decrypt(path, file, key)
    }

    fn decrypt(path: &Path, file: VaultFile, key: Zeroizing<[u8; 32]>) -> Result<Self, Error> {
        let header = file.header;
        let nonce = hex::decode(&file.nonce).map_err(|_| Error::Damaged("invalid nonce"))?;
        if nonce.len() != NONCE_BYTES {
            return Err(Error::Damaged("invalid nonce"));
        }
        let ciphertext =
            hex::decode(&file.ciphertext).map_err(|_| Error::Damaged("invalid contents"))?;

        let aad = header_bytes(&header)?;
        let plaintext = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice()))
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| Error::WrongPasswordOrTampered)?;
        let contents = serde_json::from_slice(&plaintext)
            .map_err(|_| Error::Damaged("invalid contents"))?;

        Ok(Self {
            path: path.to_path_buf(),
            header,
            key,
            contents,
        })
    }

    /// Re-encrypts the vault under a new password. Copies on this PC that still
    /// open with the old password are deleted, because the reason for changing it
    /// may be that the old one leaked. Backups saved elsewhere can't be reached.
    pub fn change_password(&mut self, current: &str, new: &str) -> Result<(), Error> {
        if *derive_key(current, &self.header.kdf)? != *self.key {
            return Err(Error::WrongPasswordOrTampered);
        }
        if new.chars().count() < MIN_PASSWORD_CHARS {
            return Err(Error::PasswordTooShort);
        }
        if new == current {
            return Err(Error::SamePassword);
        }

        let mut salt = [0u8; SALT_BYTES];
        OsRng.fill_bytes(&mut salt);
        let mut header = self.header.clone();
        header.kdf.salt = hex::encode(salt);
        let next = Self {
            path: self.path.clone(),
            key: derive_key(new, &header.kdf)?,
            header,
            contents: self.contents.clone(),
        };
        next.write(&next.contents)?;
        *self = next;

        for extension in ["bak", BEFORE_RESTORE, QUICK_UNLOCK] {
            let old_copy = append_extension(&self.path, extension);
            if old_copy.exists() {
                fs::remove_file(&old_copy).map_err(|_| Error::OldCopyRemains(old_copy))?;
            }
        }
        Ok(())
    }

    /// Lets `secret` open the vault without the master password. The secret must
    /// come from something that guards it, such as a Windows Hello signature.
    pub fn enable_quick_unlock(&self, secret: &[u8]) -> Result<(), Error> {
        let aad = quick_unlock_aad(&self.header);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = quick_unlock_cipher(secret)?
            .encrypt(
                &nonce,
                Payload {
                    msg: self.key.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| Error::QuickUnlockFailed)?;
        let file = QuickUnlockFile {
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        };
        let bytes =
            serde_json::to_vec(&file).map_err(|_| Error::Damaged("couldn't encode contents"))?;
        replace_file(&append_extension(&self.path, QUICK_UNLOCK), &bytes)?;
        Ok(())
    }

    pub fn open_with_quick_unlock(path: &Path, secret: &[u8]) -> Result<Self, Error> {
        let file = parse_file(&fs::read(path)?)?;
        let sealed: QuickUnlockFile =
            serde_json::from_slice(&fs::read(append_extension(path, QUICK_UNLOCK))?)
                .map_err(|_| Error::QuickUnlockFailed)?;
        let nonce = hex::decode(&sealed.nonce).map_err(|_| Error::QuickUnlockFailed)?;
        let ciphertext = hex::decode(&sealed.ciphertext).map_err(|_| Error::QuickUnlockFailed)?;
        if nonce.len() != NONCE_BYTES {
            return Err(Error::QuickUnlockFailed);
        }

        let aad = quick_unlock_aad(&file.header);
        let opened = quick_unlock_cipher(secret)?
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| Error::QuickUnlockFailed)?;
        let mut key = Zeroizing::new([0u8; 32]);
        if opened.len() != key.len() {
            return Err(Error::QuickUnlockFailed);
        }
        key.copy_from_slice(&opened);
        Self::decrypt(path, file, key).map_err(|_| Error::QuickUnlockFailed)
    }
    pub fn entries(&self) -> &[Entry] {
        &self.contents.entries
    }

    pub fn entry(&self, id: u32) -> Option<&Entry> {
        self.contents.entries.iter().find(|e| e.id == id)
    }

    pub fn add(&mut self, label: &str, username: &str, password: &str) -> Result<u32, Error> {
        if password.is_empty() {
            return Err(Error::InvalidAccount("Enter a password."));
        }
        let label = clean_label(label)?;

        let mut next = self.contents.clone();
        let id = next.next_id;
        next.next_id = id
            .checked_add(1)
            .ok_or(Error::InvalidAccount("Too many accounts."))?;
        next.entries.push(Entry {
            id,
            label,
            username: username.trim().to_string(),
            password: password.to_string(),
            matches: Vec::new(),
        });
        self.commit(next)?;
        Ok(id)
    }

    /// Remembers that this account is used with `key`.
    pub fn add_match(&mut self, id: u32, key: &str) -> Result<(), Error> {
        let mut next = self.contents.clone();
        let entry = next
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or(Error::AccountNotFound)?;
        if entry.matches.iter().any(|m| m == key) {
            return Ok(());
        }
        entry.matches.push(key.to_string());
        self.commit(next)
    }

    /// Forgets that this account is used with `key`.
    pub fn remove_match(&mut self, id: u32, key: &str) -> Result<(), Error> {
        let mut next = self.contents.clone();
        let entry = next
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or(Error::AccountNotFound)?;
        entry.matches.retain(|m| m != key);
        self.commit(next)
    }

    /// Passing `None` as the password keeps the current one.
    pub fn update(
        &mut self,
        id: u32,
        label: &str,
        username: &str,
        password: Option<&str>,
    ) -> Result<(), Error> {
        let label = clean_label(label)?;

        let mut next = self.contents.clone();
        let entry = next
            .entries
            .iter_mut()
            .find(|e| e.id == id)
            .ok_or(Error::AccountNotFound)?;
        entry.label = label;
        entry.username = username.trim().to_string();
        if let Some(password) = password {
            if password.is_empty() {
                return Err(Error::InvalidAccount("Enter a password."));
            }
            entry.password = password.to_string();
        }
        self.commit(next)
    }

    pub fn remove(&mut self, id: u32) -> Result<(), Error> {
        let mut next = self.contents.clone();
        let before = next.entries.len();
        next.entries.retain(|e| e.id != id);
        if next.entries.len() == before {
            return Err(Error::AccountNotFound);
        }
        self.commit(next)
    }

    /// Memory only changes after the new contents are safely on disk.
    fn commit(&mut self, next: Contents) -> Result<(), Error> {
        self.write(&next)?;
        self.contents = next;
        Ok(())
    }

    fn write(&self, contents: &Contents) -> Result<(), Error> {
        let plaintext = Zeroizing::new(
            serde_json::to_vec(contents).map_err(|_| Error::Damaged("couldn't encode contents"))?,
        );
        self.write_plaintext(&plaintext)
    }

    fn write_plaintext(&self, plaintext: &[u8]) -> Result<(), Error> {
        let aad = header_bytes(&self.header)?;
        // A fresh nonce on every save: AES-GCM breaks if one is ever reused.
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(self.key.as_slice()))
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Damaged("couldn't encrypt contents"))?;

        let file = VaultFile {
            header: self.header.clone(),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        };
        let bytes = serde_json::to_vec_pretty(&file)
            .map_err(|_| Error::Damaged("couldn't encode contents"))?;
        write_atomic(&self.path, &bytes)?;
        Ok(())
    }
}

fn clean_label(label: &str) -> Result<String, Error> {
    let label = label.trim();
    if label.is_empty() {
        return Err(Error::InvalidAccount("Enter a name for this account."));
    }
    Ok(label.to_string())
}

fn parse_file(bytes: &[u8]) -> Result<VaultFile, Error> {
    let file: VaultFile =
        serde_json::from_slice(bytes).map_err(|_| Error::Damaged("it isn't a vault file"))?;
    if file.header.format != FORMAT {
        return Err(Error::Damaged("it isn't a vault file"));
    }
    if file.header.version != VERSION {
        return Err(Error::Damaged("it was made by a different app version"));
    }
    Ok(file)
}

fn quick_unlock_cipher(secret: &[u8]) -> Result<Aes256Gcm, Error> {
    if secret.is_empty() {
        return Err(Error::QuickUnlockFailed);
    }
    let mut hash = Sha256::new();
    hash.update(b"crypass-quick-unlock");
    hash.update(secret);
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&hash.finalize());
    Ok(Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_slice())))
}

/// Ties the sealed key to this vault, so it can't be swapped in for another one.
fn quick_unlock_aad(header: &Header) -> Vec<u8> {
    format!("{FORMAT}:{}", header.kdf.salt).into_bytes()
}

fn header_bytes(header: &Header) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(header).map_err(|_| Error::Damaged("invalid header"))
}

fn derive_key(password: &str, kdf: &Kdf) -> Result<Zeroizing<[u8; 32]>, Error> {
    if kdf.algorithm != "argon2id"
        || kdf.memory_kib > MAX_MEMORY_KIB
        || kdf.iterations > MAX_ITERATIONS
        || kdf.parallelism > MAX_PARALLELISM
    {
        return Err(Error::Damaged("invalid key settings"));
    }
    let salt = hex::decode(&kdf.salt).map_err(|_| Error::Damaged("invalid key settings"))?;
    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
        .map_err(|_| Error::Damaged("invalid key settings"))?;

    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), &salt, key.as_mut_slice())
        .map_err(|_| Error::Damaged("invalid key settings"))?;
    Ok(key)
}

/// Copies the encrypted vault file to `destination` and confirms the copy
/// matches. It needs no password, and the copy opens with the same master
/// password as the vault it came from.
pub fn export_backup(vault_path: &Path, destination: &Path) -> Result<(), Error> {
    if destination.exists() && fs::canonicalize(vault_path)? == fs::canonicalize(destination)? {
        return Err(Error::InvalidBackupDestination);
    }

    let bytes = fs::read(vault_path)?;
    let file: VaultFile =
        serde_json::from_slice(&bytes).map_err(|_| Error::Damaged("it isn't a vault file"))?;
    if file.header.format != FORMAT {
        return Err(Error::Damaged("it isn't a vault file"));
    }

    replace_file(destination, &bytes)?;
    if fs::read(destination)? != bytes {
        return Err(Error::BackupMismatch);
    }
    Ok(())
}

/// True if `open_with_quick_unlock` has something to work with.
pub fn quick_unlock_enabled(vault_path: &Path) -> bool {
    append_extension(vault_path, QUICK_UNLOCK).exists()
}

pub fn disable_quick_unlock(vault_path: &Path) -> Result<(), Error> {
    let path = append_extension(vault_path, QUICK_UNLOCK);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

/// Replaces the vault with a backup, once the backup's own master password has
/// opened it. A vault already here is kept as `<name>.before-restore`, so a
/// mistaken restore can be undone by restoring that file.
pub fn restore_backup(backup: &Path, vault_path: &Path, password: &str) -> Result<Vault, Error> {
    if vault_path.exists() && fs::canonicalize(vault_path)? == fs::canonicalize(backup)? {
        return Err(Error::InvalidBackupDestination);
    }

    // Checking and installing the same bytes means the file can't change in between.
    let bytes = fs::read(backup)?;
    let vault = Vault::open_bytes(vault_path, &bytes, password)?;

    if vault_path.exists() {
        replace_file(
            &append_extension(vault_path, BEFORE_RESTORE),
            &fs::read(vault_path)?,
        )?;
    }
    replace_file(vault_path, &bytes)?;
    // It holds the replaced vault's key, which can't open this one.
    disable_quick_unlock(vault_path)?;
    Ok(vault)
}

/// A crash mid-save leaves the old vault intact, and the previous version is
/// kept as `<name>.bak`. Both files are always encrypted.
fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if path.exists() {
        fs::copy(path, append_extension(path, "bak"))?;
    }
    replace_file(path, bytes)
}

fn replace_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temporary = append_extension(path, "tmp");
    let mut file = File::create(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)
}

fn append_extension(path: &Path, extension: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(".");
    name.push(extension);
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: &str = "correct horse battery";
    const NEW_MASTER: &str = "a brand new passphrase";
    const FAST: KdfSettings = KdfSettings {
        memory_kib: 64,
        iterations: 1,
        parallelism: 1,
    };

    fn new_vault() -> (tempfile::TempDir, PathBuf, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.crypass");
        let vault = Vault::create_with(&path, MASTER, FAST).unwrap();
        (dir, path, vault)
    }

    /// Flips one hex character inside a JSON string field of the vault file.
    fn flip_field(path: &Path, field: &str) {
        let mut json: serde_json::Value =
            serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        let slot = match field {
            "salt" => &mut json["header"]["kdf"]["salt"],
            other => &mut json[other],
        };
        let mut text = slot.as_str().unwrap().to_string();
        let first = if text.starts_with('0') { "1" } else { "0" };
        text.replace_range(0..1, first);
        *slot = serde_json::Value::String(text);
        fs::write(path, serde_json::to_vec(&json).unwrap()).unwrap();
    }

    #[test]
    fn saved_accounts_survive_reopening() {
        let (_dir, path, mut vault) = new_vault();
        let id = vault.add(" Mail ", " me@example.com ", "p@ss wörd €").unwrap();
        drop(vault);

        let vault = Vault::open(&path, MASTER).unwrap();
        let entry = vault.entry(id).unwrap();
        assert_eq!(entry.label, "Mail");
        assert_eq!(entry.username, "me@example.com");
        assert_eq!(entry.password, "p@ss wörd €");
    }

    #[test]
    fn wrong_password_is_rejected() {
        let (_dir, path, _vault) = new_vault();
        assert!(matches!(
            Vault::open(&path, "a different password"),
            Err(Error::WrongPasswordOrTampered)
        ));
    }

    #[test]
    fn secrets_never_reach_the_disk_in_plain_text() {
        let (dir, path, mut vault) = new_vault();
        vault.add("LabelMarker", "UserMarker", "SecretMarker").unwrap();
        vault.add("Second", "Other", "SecretMarker2").unwrap();

        assert!(path.with_file_name("vault.crypass.bak").exists());
        for file in fs::read_dir(dir.path()).unwrap() {
            let bytes = fs::read(file.unwrap().path()).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            for marker in ["LabelMarker", "UserMarker", "SecretMarker", MASTER] {
                assert!(!text.contains(marker), "{marker} found on disk");
            }
        }
    }

    #[test]
    fn changed_contents_are_rejected() {
        let (_dir, path, mut vault) = new_vault();
        vault.add("Mail", "me", "secret").unwrap();
        flip_field(&path, "ciphertext");
        assert!(matches!(
            Vault::open(&path, MASTER),
            Err(Error::WrongPasswordOrTampered)
        ));
    }

    #[test]
    fn changed_header_is_rejected() {
        let (_dir, path, _vault) = new_vault();
        flip_field(&path, "salt");
        assert!(matches!(
            Vault::open(&path, MASTER),
            Err(Error::WrongPasswordOrTampered)
        ));
    }

    #[test]
    fn oversized_key_settings_are_rejected_before_allocating() {
        let (_dir, path, _vault) = new_vault();
        let mut json: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        json["header"]["kdf"]["memory_kib"] = serde_json::json!(u32::MAX);
        fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
        assert!(matches!(Vault::open(&path, MASTER), Err(Error::Damaged(_))));
    }

    #[test]
    fn a_file_that_is_not_a_vault_is_reported_as_damaged() {
        let (_dir, path, _vault) = new_vault();
        fs::write(&path, "not a vault").unwrap();
        assert!(matches!(Vault::open(&path, MASTER), Err(Error::Damaged(_))));
    }

    #[test]
    fn create_never_overwrites_an_existing_vault() {
        let (_dir, path, _vault) = new_vault();
        assert!(matches!(
            Vault::create_with(&path, MASTER, FAST),
            Err(Error::AlreadyExists)
        ));
    }

    #[test]
    fn short_master_passwords_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.crypass");
        assert!(matches!(
            Vault::create_with(&path, "too short", FAST),
            Err(Error::PasswordTooShort)
        ));
        assert!(!path.exists());
    }

    #[test]
    fn update_can_keep_or_replace_the_password() {
        let (_dir, path, mut vault) = new_vault();
        let id = vault.add("Mail", "me", "first").unwrap();

        vault.update(id, "Inbox", "you", None).unwrap();
        let entry = vault.entry(id).unwrap();
        assert_eq!((entry.label.as_str(), entry.password.as_str()), ("Inbox", "first"));

        vault.update(id, "Inbox", "you", Some("second")).unwrap();
        drop(vault);
        let vault = Vault::open(&path, MASTER).unwrap();
        assert_eq!(vault.entry(id).unwrap().password, "second");
    }

    #[test]
    fn removed_accounts_stay_removed_and_ids_are_not_reused() {
        let (_dir, path, mut vault) = new_vault();
        let first = vault.add("One", "a", "x").unwrap();
        vault.remove(first).unwrap();
        assert!(matches!(vault.remove(first), Err(Error::AccountNotFound)));
        let second = vault.add("Two", "b", "y").unwrap();
        assert_ne!(first, second);
        drop(vault);

        let vault = Vault::open(&path, MASTER).unwrap();
        assert!(vault.entry(first).is_none());
        assert_eq!(vault.entries().len(), 1);
    }

    #[test]
    fn invalid_accounts_are_rejected_without_changes() {
        let (_dir, _path, mut vault) = new_vault();
        assert!(matches!(vault.add("  ", "me", "secret"), Err(Error::InvalidAccount(_))));
        assert!(matches!(vault.add("Mail", "me", ""), Err(Error::InvalidAccount(_))));
        assert!(vault.entries().is_empty());
    }

    #[test]
    fn a_failed_save_leaves_memory_unchanged() {
        let (dir, path, mut vault) = new_vault();
        let id = vault.add("Mail", "me", "secret").unwrap();

        // A directory at the temporary path makes the next save fail.
        fs::create_dir(dir.path().join("vault.crypass.tmp")).unwrap();
        assert!(matches!(vault.add("Second", "you", "other"), Err(Error::Io(_))));
        assert_eq!(vault.entries().len(), 1);
        assert!(vault.entry(id).is_some());
        assert!(path.exists());
    }

    #[test]
    fn a_vault_from_before_site_matching_still_opens_and_keeps_its_accounts() {
        let (_dir, path, vault) = new_vault();
        // The exact contents an earlier version of the app wrote.
        vault
            .write_plaintext(
                br#"{"next_id":2,"entries":[{"id":1,"label":"Old","username":"me","password":"keep me"}]}"#,
            )
            .unwrap();
        drop(vault);

        let mut vault = Vault::open(&path, MASTER).unwrap();
        let entry = vault.entry(1).unwrap();
        assert_eq!(entry.password, "keep me");
        assert!(entry.matches.is_empty());

        vault.add_match(1, "https://bank.com").unwrap();
        drop(vault);
        let vault = Vault::open(&path, MASTER).unwrap();
        assert_eq!(vault.entry(1).unwrap().password, "keep me");
        assert_eq!(vault.entry(1).unwrap().matches, ["https://bank.com"]);
    }

    #[test]
    fn saved_sites_survive_edits_and_are_not_duplicated_or_readable_on_disk() {
        let (_dir, path, mut vault) = new_vault();
        let id = vault.add("Mail", "me", "secret").unwrap();
        vault.add_match(id, "https://sitemarker.example").unwrap();
        vault.add_match(id, "https://sitemarker.example").unwrap();
        vault.update(id, "Inbox", "you", None).unwrap();

        assert_eq!(vault.entry(id).unwrap().matches.len(), 1);
        assert!(!fs::read_to_string(&path).unwrap().contains("sitemarker"));
        assert!(matches!(vault.add_match(99, "x"), Err(Error::AccountNotFound)));
    }

    #[test]
    fn a_removed_site_stays_removed_and_leaves_the_rest_alone() {
        let (_dir, path, mut vault) = new_vault();
        let id = vault.add("Mail", "me", "secret").unwrap();
        vault.add_match(id, "https://one.example").unwrap();
        vault.add_match(id, "https://two.example").unwrap();

        vault.remove_match(id, "https://one.example").unwrap();
        // Removing something that isn't there changes nothing.
        vault.remove_match(id, "https://never.example").unwrap();
        assert!(matches!(vault.remove_match(99, "x"), Err(Error::AccountNotFound)));
        drop(vault);

        let vault = Vault::open(&path, MASTER).unwrap();
        let entry = vault.entry(id).unwrap();
        assert_eq!(entry.matches, ["https://two.example"]);
        assert_eq!(entry.password, "secret");
    }

    #[test]
    fn a_backup_opens_with_the_master_password_and_has_every_account() {
        let (dir, path, mut vault) = new_vault();
        let id = vault.add("Mail", "me", "secret").unwrap();
        let backup = dir.path().join("backup.crypass");

        export_backup(&path, &backup).unwrap();

        let restored = Vault::open(&backup, MASTER).unwrap();
        assert_eq!(restored.entry(id).unwrap().password, "secret");
        assert!(matches!(
            Vault::open(&backup, "a different password"),
            Err(Error::WrongPasswordOrTampered)
        ));
    }

    #[test]
    fn a_backup_stays_encrypted_and_leaves_no_extra_files() {
        let (dir, path, mut vault) = new_vault();
        vault.add("LabelMarker", "UserMarker", "SecretMarker").unwrap();
        let folder = dir.path().join("usb");
        fs::create_dir(&folder).unwrap();
        let backup = folder.join("backup.crypass");

        export_backup(&path, &backup).unwrap();
        // Saving over an older backup must not leave extra copies either.
        export_backup(&path, &backup).unwrap();

        let names: Vec<_> = fs::read_dir(&folder)
            .unwrap()
            .map(|f| f.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(names, ["backup.crypass"]);
        let text = fs::read_to_string(&backup).unwrap();
        for marker in ["LabelMarker", "UserMarker", "SecretMarker"] {
            assert!(!text.contains(marker), "{marker} found in backup");
        }
    }

    #[test]
    fn a_new_backup_replaces_an_older_one() {
        let (dir, path, mut vault) = new_vault();
        let backup = dir.path().join("backup.crypass");
        export_backup(&path, &backup).unwrap();
        let id = vault.add("Mail", "me", "secret").unwrap();

        export_backup(&path, &backup).unwrap();
        assert!(Vault::open(&backup, MASTER).unwrap().entry(id).is_some());
    }

    #[test]
    fn a_backup_cannot_overwrite_the_vault_itself() {
        let (_dir, path, mut vault) = new_vault();
        let id = vault.add("Mail", "me", "secret").unwrap();
        assert!(matches!(
            export_backup(&path, &path),
            Err(Error::InvalidBackupDestination)
        ));
        assert!(Vault::open(&path, MASTER).unwrap().entry(id).is_some());
    }

    #[test]
    fn a_damaged_vault_never_replaces_a_good_backup() {
        let (dir, path, _vault) = new_vault();
        let backup = dir.path().join("backup.crypass");
        export_backup(&path, &backup).unwrap();

        fs::write(&path, "not a vault").unwrap();
        assert!(matches!(export_backup(&path, &backup), Err(Error::Damaged(_))));
        assert!(Vault::open(&backup, MASTER).is_ok());
    }

    #[test]
    fn a_changed_password_replaces_the_old_one_and_keeps_every_account() {
        let (_dir, path, mut vault) = new_vault();
        let id = vault.add("Mail", "me", "secret").unwrap();
        vault.add_match(id, "https://mail.example").unwrap();

        vault.change_password(MASTER, NEW_MASTER).unwrap();
        // Saving afterwards must use the new key.
        vault.update(id, "Inbox", "me", None).unwrap();
        drop(vault);

        assert!(matches!(
            Vault::open(&path, MASTER),
            Err(Error::WrongPasswordOrTampered)
        ));
        let vault = Vault::open(&path, NEW_MASTER).unwrap();
        let entry = vault.entry(id).unwrap();
        assert_eq!(entry.label, "Inbox");
        assert_eq!(entry.password, "secret");
        assert_eq!(entry.matches, ["https://mail.example"]);
    }

    #[test]
    fn a_refused_password_change_changes_nothing() {
        let (_dir, path, mut vault) = new_vault();
        let id = vault.add("Mail", "me", "secret").unwrap();

        assert!(matches!(
            vault.change_password("not the password", NEW_MASTER),
            Err(Error::WrongPasswordOrTampered)
        ));
        assert!(matches!(
            vault.change_password(MASTER, "too short"),
            Err(Error::PasswordTooShort)
        ));
        assert!(matches!(
            vault.change_password(MASTER, MASTER),
            Err(Error::SamePassword)
        ));

        vault.update(id, "Inbox", "me", None).unwrap();
        drop(vault);
        assert!(Vault::open(&path, MASTER).is_ok());
    }

    #[test]
    fn a_failed_password_change_keeps_the_old_password_working() {
        let (dir, path, mut vault) = new_vault();
        // A directory at the temporary path makes the save fail.
        fs::create_dir(dir.path().join("vault.crypass.tmp")).unwrap();
        assert!(matches!(
            vault.change_password(MASTER, NEW_MASTER),
            Err(Error::Io(_))
        ));
        fs::remove_dir(dir.path().join("vault.crypass.tmp")).unwrap();

        vault.add("Mail", "me", "secret").unwrap();
        drop(vault);
        assert_eq!(Vault::open(&path, MASTER).unwrap().entries().len(), 1);
    }

    #[test]
    fn no_copy_on_this_pc_opens_with_the_old_password_after_a_change() {
        let (dir, path, mut vault) = new_vault();
        vault.add("Mail", "me", "secret").unwrap();
        let backup = dir.path().join("backup.crypass");
        export_backup(&path, &backup).unwrap();
        restore_backup(&backup, &path, MASTER).unwrap();
        vault.enable_quick_unlock(b"signature").unwrap();
        assert!(path.with_file_name("vault.crypass.before-restore").exists());

        vault.change_password(MASTER, NEW_MASTER).unwrap();

        fs::remove_file(&backup).unwrap();
        for file in fs::read_dir(dir.path()).unwrap() {
            let file = file.unwrap().path();
            assert!(
                Vault::open(&file, MASTER).is_err(),
                "{} still opens with the old password",
                file.display()
            );
        }
        assert!(!quick_unlock_enabled(&path));
    }

    #[test]
    fn restoring_replaces_the_vault_and_keeps_the_old_one_aside() {
        let (dir, path, mut vault) = new_vault();
        let old = vault.add("Old", "me", "old secret").unwrap();
        let backup = dir.path().join("backup.crypass");
        export_backup(&path, &backup).unwrap();
        let newer = vault.add("Newer", "me", "newer secret").unwrap();
        vault.change_password(MASTER, NEW_MASTER).unwrap();
        drop(vault);

        // The backup's password is the one that counts, not the current vault's.
        let restored = restore_backup(&backup, &path, MASTER).unwrap();
        assert!(restored.entry(old).is_some());
        assert!(restored.entry(newer).is_none());
        drop(restored);

        assert!(Vault::open(&path, MASTER).unwrap().entry(newer).is_none());
        let aside = path.with_file_name("vault.crypass.before-restore");
        assert!(Vault::open(&aside, NEW_MASTER).unwrap().entry(newer).is_some());
    }

    #[test]
    fn restoring_works_when_no_vault_exists_yet() {
        let (dir, path, mut vault) = new_vault();
        let id = vault.add("Mail", "me", "secret").unwrap();
        drop(vault);

        let fresh = dir.path().join("new-pc").join("vault.crypass");
        fs::create_dir(fresh.parent().unwrap()).unwrap();
        let mut restored = restore_backup(&path, &fresh, MASTER).unwrap();
        assert_eq!(restored.entry(id).unwrap().password, "secret");

        // It must save to the new location, not the backup's.
        restored.add("Second", "you", "other").unwrap();
        drop(restored);
        assert_eq!(Vault::open(&fresh, MASTER).unwrap().entries().len(), 2);
        assert_eq!(Vault::open(&path, MASTER).unwrap().entries().len(), 1);
    }

    #[test]
    fn a_refused_restore_leaves_the_vault_untouched() {
        let (dir, path, mut vault) = new_vault();
        vault.add("Mail", "me", "secret").unwrap();
        let backup = dir.path().join("backup.crypass");
        export_backup(&path, &backup).unwrap();
        vault.add("Second", "you", "other").unwrap();
        let before = fs::read(&path).unwrap();

        assert!(matches!(
            restore_backup(&backup, &path, "not the password"),
            Err(Error::WrongPasswordOrTampered)
        ));
        fs::write(&backup, "not a vault").unwrap();
        assert!(matches!(
            restore_backup(&backup, &path, MASTER),
            Err(Error::Damaged(_))
        ));
        assert!(matches!(
            restore_backup(&path, &path, MASTER),
            Err(Error::InvalidBackupDestination)
        ));

        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(!path.with_file_name("vault.crypass.before-restore").exists());
    }

    #[test]
    fn restoring_turns_off_quick_unlock() {
        let (dir, path, vault) = new_vault();
        let backup = dir.path().join("backup.crypass");
        export_backup(&path, &backup).unwrap();
        vault.enable_quick_unlock(b"signature").unwrap();

        restore_backup(&backup, &path, MASTER).unwrap();
        assert!(!quick_unlock_enabled(&path));
    }

    #[test]
    fn quick_unlock_opens_the_vault_only_with_the_right_secret() {
        let (_dir, path, mut vault) = new_vault();
        let id = vault.add("Mail", "me", "secret").unwrap();
        assert!(!quick_unlock_enabled(&path));

        vault.enable_quick_unlock(b"signature").unwrap();
        assert!(quick_unlock_enabled(&path));
        drop(vault);

        let mut opened = Vault::open_with_quick_unlock(&path, b"signature").unwrap();
        assert_eq!(opened.entry(id).unwrap().password, "secret");
        assert!(matches!(
            Vault::open_with_quick_unlock(&path, b"wrong"),
            Err(Error::QuickUnlockFailed)
        ));
        assert!(matches!(
            Vault::open_with_quick_unlock(&path, b""),
            Err(Error::QuickUnlockFailed)
        ));

        // Saves made after a quick unlock still open with the master password.
        opened.add("Second", "you", "other").unwrap();
        drop(opened);
        assert_eq!(Vault::open(&path, MASTER).unwrap().entries().len(), 2);
    }

    #[test]
    fn quick_unlock_stores_no_readable_key_and_can_be_turned_off() {
        let (_dir, path, vault) = new_vault();
        vault.enable_quick_unlock(b"signature").unwrap();

        let sealed = fs::read_to_string(path.with_file_name("vault.crypass.hello")).unwrap();
        assert!(!sealed.contains(&hex::encode(vault.key.as_slice())));

        disable_quick_unlock(&path).unwrap();
        assert!(!quick_unlock_enabled(&path));
        assert!(Vault::open_with_quick_unlock(&path, b"signature").is_err());
        disable_quick_unlock(&path).unwrap();
    }

    #[test]
    fn a_sealed_key_cannot_be_moved_to_another_vault() {
        let (dir, path, vault) = new_vault();
        vault.enable_quick_unlock(b"signature").unwrap();

        let other = dir.path().join("other.crypass");
        Vault::create_with(&other, MASTER, FAST).unwrap();
        fs::copy(
            path.with_file_name("vault.crypass.hello"),
            dir.path().join("other.crypass.hello"),
        )
        .unwrap();
        assert!(matches!(
            Vault::open_with_quick_unlock(&other, b"signature"),
            Err(Error::QuickUnlockFailed)
        ));
    }

    #[test]
    fn default_key_settings_work() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.crypass");
        Vault::create(&path, MASTER).unwrap();
        assert!(Vault::open(&path, MASTER).is_ok());
    }
}
