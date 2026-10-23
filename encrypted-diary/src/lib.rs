//! Uses argon2 to generate key from password
//! encrypted with ChaCha20-Poly1305 (typically more resistant to side channel attacks compared to AES)
//! plaintxt is only written to a temp file in /tmp with vim as the editor
//! Each diary stored as salt + nonce + ciphertext(including tag)
//! uses rpassword for password input

use argon2::Argon2;
use chacha20poly1305::aead::{OsRng, rand_core::RngCore};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit},
};
use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;

const VIM_ARGS: &[&str] = &[
    "-n",
    "-i",
    "NONE",
    "-c",
    "set nobackup nowritebackup noundofile",
];

pub enum Action {
    New,
    Read,
    Edit,
}

impl Action {
    fn string_parse(s: &str) -> Result<Self, String> {
        match s.trim().to_lowercase().as_str() {
            "new" => Ok(Action::New),
            "read" => Ok(Action::Read),
            "edit" => Ok(Action::Edit),
            _ => Err(format!("'{}' is not a valid command", s)),
        }
    }
}

///form in which input is stored
pub struct Config {
    pub action: Action,
    pub filename: String,
}

impl Config {
    pub fn new(args: &[String]) -> Result<Config, String> {
        if args.len() < 3 {
            return Err("usage: diary <new|read|edit> <file>".to_string());
        }

        let action = Action::string_parse(&args[1])?;
        let filename = args[2].clone();

        Ok(Config { action, filename })
    }
}

///form in which diary's data is stored
struct EncryptedData {
    salt: [u8; 16],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl EncryptedData {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.salt);
        bytes.extend_from_slice(&self.nonce);
        bytes.extend_from_slice(&self.ciphertext);
        bytes
    }

    pub fn from_bytes(data: &[u8]) -> Result<EncryptedData, String> {
        if data.len() < 16 + 12 + 16 {
            return Err("file is too short to be a diary".to_string());
        }

        let salt: [u8; 16] = data[0..16].try_into().map_err(|_| "corrupt file")?;
        let nonce: [u8; 12] = data[16..28].try_into().map_err(|_| "corrupt file")?;
        let ciphertext = data[28..].to_vec();
        Ok(EncryptedData {
            salt,
            nonce,
            ciphertext,
        })
    }
}

pub fn run(config: Config) -> Result<(), Box<dyn Error>> {
    match config.action {
        Action::New => cmd_new(&config.filename)?,
        Action::Read => cmd_read(&config.filename)?,
        Action::Edit => cmd_edit(&config.filename)?,
    }

    Ok(())
}

/// to create new diary
fn cmd_new(filename: &str) -> Result<(), Box<dyn Error>> {
    if Path::new(filename).exists() {
        return Err(format!("'{}' already exists", filename).into());
    }

    let password = rpassword::prompt_password("Password: ")?;
    let confirm = rpassword::prompt_password("Confirm your password: ")?;

    if password != confirm {
        return Err("passwords do not match".into());
    }

    if password.is_empty() {
        return Err("password cannot be empty".into());
    }

    let plaintext =
        open_in_program("vim", VIM_ARGS, "", true)?.ok_or("editor returned no content")?;

    save(filename, &password, &plaintext)?;

    println!("Created new diary '{}'", filename);

    Ok(())
}

///to read existing diary
fn cmd_read(filename: &str) -> Result<(), Box<dyn Error>> {
    let (plaintext, _password) = load(filename)?;
    open_in_program("less", &[], &plaintext, false)?;
    Ok(())
}

///to edit existing diary
fn cmd_edit(filename: &str) -> Result<(), Box<dyn Error>> {
    let (plaintext, password) = load(filename)?;

    let edited =
        open_in_program("vim", VIM_ARGS, &plaintext, true)?.ok_or("editor returned no content")?;

    if edited == plaintext {
        println!("No changes.");
    } else {
        save(filename, &password, &edited)?;
        println!("Saved '{}'.", filename);
    }
    Ok(())
}

///generates key from password and a salt using argon2
fn derive_key(password: &str, salt: &[u8; 16]) -> Result<[u8; 32], String> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Key derivation failed: {e}"))?;

    Ok(key)
}

///encryption of plaintext with given password
fn encrypt(password: &str, plaintext: &str) -> Result<EncryptedData, String> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    let key = derive_key(password, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| "encryption failed")?;

    Ok(EncryptedData {
        salt,
        nonce: nonce.into(),
        ciphertext,
    })
}

///decryption of encrypted data with given password
fn decrypt(password: &str, data: &EncryptedData) -> Result<String, String> {
    let key = derive_key(password, &data.salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let plaintext_bytes = cipher
        .decrypt(Nonce::from_slice(&data.nonce), data.ciphertext.as_ref())
        .map_err(|_| "wrong password or file was tampered with")?;
    let plaintext = String::from_utf8(plaintext_bytes)
        .map_err(|_| "diary contents are not valid UTF-8".to_string())?;

    Ok(plaintext)
}

///loads plaintext from diary
fn load(filename: &str) -> Result<(String, String), Box<dyn Error>> {
    let bytes = fs::read(filename)?;
    let data = EncryptedData::from_bytes(&bytes)?;
    let password = rpassword::prompt_password("Password: ")?;
    let plaintext = decrypt(&password, &data)?;

    Ok((plaintext, password))
}

///handles opening the text editor
fn open_in_program(
    program: &str,
    args: &[&str],
    content: &str,
    read_back: bool,
) -> Result<Option<String>, Box<dyn Error>> {
    let mut tmp = tempfile::Builder::new()
        .prefix("diary-")
        .suffix(".txt")
        .tempfile_in("/tmp")?;
    tmp.write_all(content.as_bytes())?;
    tmp.flush()?;

    let status = Command::new(program).args(args).arg(tmp.path()).status()?;
    if !status.success() {
        return Err(format!("{} exited with an error", program).into());
    }

    let result = if read_back {
        Some(fs::read_to_string(tmp.path())?)
    } else {
        None
    };

    Ok(result)
}

///encrypts plaintext and saves in diary
fn save(filename: &str, password: &str, plaintext: &str) -> Result<(), Box<dyn Error>> {
    let data = encrypt(password, plaintext)?;
    let tmp_name = format!("{}.tmp", filename);
    fs::write(&tmp_name, data.to_bytes())?;
    fs::rename(&tmp_name, filename)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let data = encrypt("hairy", "dear diary").unwrap();
        assert_eq!(decrypt("hairy", &data).unwrap(), "dear diary");
    }

    #[test]
    fn wrong_password_fails() {
        let data = encrypt("hairy", "dear diary").unwrap();
        assert!(decrypt("wrong", &data).is_err());
    }

    #[test]
    fn tampering_fails() {
        let mut data = encrypt("hairy", "dear diary").unwrap();
        data.ciphertext[0] ^= 1; // flipping a bit to tamper w data
        assert!(decrypt("hairy", &data).is_err());
    }
}
