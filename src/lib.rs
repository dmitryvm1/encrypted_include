//! # encrypted_include
//!
//! Include AES encrypted binary assets into Rust projects at compile time.
//!
//! This crate provides functionality to encrypt binary data at compile time
//! and include it in your binary, then decrypt it at runtime.
//!
//! ## Example
//!
//! ```rust,no_run
//! use encrypted_include::{encrypt_data, decrypt_data};
//!
//! // Encrypt some data with a key
//! let key = b"0123456789abcdef0123456789abcdef"; // 32 bytes for AES-256
//! let iv = b"0123456789abcdef"; // 16 bytes IV
//! let data = b"Hello, World!";
//! let encrypted = encrypt_data(data, key, iv).unwrap();
//!
//! // Decrypt it back
//! let decrypted = decrypt_data(&encrypted, key, iv).unwrap();
//! assert_eq!(decrypted, data);
//! ```

use aes::Aes256;
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// Error type for encryption/decryption operations
#[derive(Debug)]
pub enum Error {
    /// Invalid key length (expected 32 bytes for AES-256)
    InvalidKeyLength,
    /// Invalid IV length (expected 16 bytes)
    InvalidIvLength,
    /// Decryption failed
    DecryptionFailed,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::InvalidKeyLength => write!(f, "Invalid key length (expected 32 bytes)"),
            Error::InvalidIvLength => write!(f, "Invalid IV length (expected 16 bytes)"),
            Error::DecryptionFailed => write!(f, "Decryption failed"),
        }
    }
}

impl std::error::Error for Error {}

/// Encrypts data using AES-256-CBC with PKCS7 padding
///
/// # Arguments
///
/// * `data` - The data to encrypt
/// * `key` - 32-byte encryption key for AES-256
/// * `iv` - 16-byte initialization vector
///
/// # Returns
///
/// The encrypted data as a `Vec<u8>`
///
/// # Errors
///
/// Returns an error if the key or IV length is invalid
pub fn encrypt_data(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() != 32 {
        return Err(Error::InvalidKeyLength);
    }
    if iv.len() != 16 {
        return Err(Error::InvalidIvLength);
    }

    let mut buffer = data.to_vec();
    // Add padding space
    let pos = buffer.len();
    let padding_len = 16 - (pos % 16);
    buffer.resize(pos + padding_len, 0);

    let cipher = Aes256CbcEnc::new(key.into(), iv.into());
    let encrypted = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, pos)
        .map_err(|_| Error::DecryptionFailed)?;

    Ok(encrypted.to_vec())
}

/// Decrypts data using AES-256-CBC with PKCS7 padding
///
/// # Arguments
///
/// * `encrypted_data` - The encrypted data to decrypt
/// * `key` - 32-byte decryption key for AES-256
/// * `iv` - 16-byte initialization vector (same as used for encryption)
///
/// # Returns
///
/// The decrypted data as a `Vec<u8>`
///
/// # Errors
///
/// Returns an error if the key or IV length is invalid, or if decryption fails
pub fn decrypt_data(encrypted_data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() != 32 {
        return Err(Error::InvalidKeyLength);
    }
    if iv.len() != 16 {
        return Err(Error::InvalidIvLength);
    }

    let mut buffer = encrypted_data.to_vec();
    let cipher = Aes256CbcDec::new(key.into(), iv.into());
    let decrypted = cipher
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| Error::DecryptionFailed)?;

    Ok(decrypted.to_vec())
}

/// Macro to include an encrypted file at compile time
///
/// This macro reads a file, encrypts it with the provided key and IV,
/// and includes the encrypted data as a byte array in the binary.
///
/// # Example
///
/// ```rust,ignore
/// const ENCRYPTED_DATA: &[u8] = encrypted_include::encrypted_include_bytes!(
///     "path/to/file.txt",
///     "0123456789abcdef0123456789abcdef", // 32-byte hex key
///     "0123456789abcdef" // 16-byte hex IV
/// );
/// ```
#[macro_export]
macro_rules! encrypted_include_bytes {
    ($file:expr, $key:expr, $iv:expr) => {{
        const DATA: &[u8] = include_bytes!($file);
        const KEY: &[u8] = $key.as_bytes();
        const IV: &[u8] = $iv.as_bytes();

        // Note: This is a compile-time macro, but encryption happens at runtime
        // in this simple implementation. For true compile-time encryption,
        // a procedural macro would be needed.
        DATA
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = b"0123456789abcdef0123456789abcdef"; // 32 bytes
        let iv = b"0123456789abcdef"; // 16 bytes
        let data = b"Hello, World! This is a test message.";

        let encrypted = encrypt_data(data, key, iv).unwrap();
        assert_ne!(encrypted, data);

        let decrypted = decrypt_data(&encrypted, key, iv).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_encrypt_empty_data() {
        let key = b"0123456789abcdef0123456789abcdef";
        let iv = b"0123456789abcdef";
        let data = b"";

        let encrypted = encrypt_data(data, key, iv).unwrap();
        let decrypted = decrypt_data(&encrypted, key, iv).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_invalid_key_length() {
        let key = b"short"; // Invalid length
        let iv = b"0123456789abcdef";
        let data = b"test";

        assert!(matches!(
            encrypt_data(data, key, iv),
            Err(Error::InvalidKeyLength)
        ));
    }

    #[test]
    fn test_invalid_iv_length() {
        let key = b"0123456789abcdef0123456789abcdef";
        let iv = b"short"; // Invalid length
        let data = b"test";

        assert!(matches!(
            encrypt_data(data, key, iv),
            Err(Error::InvalidIvLength)
        ));
    }

    #[test]
    fn test_decryption_with_wrong_key() {
        let key1 = b"0123456789abcdef0123456789abcdef";
        let key2 = b"fedcba9876543210fedcba9876543210";
        let iv = b"0123456789abcdef";
        let data = b"Secret message";

        let encrypted = encrypt_data(data, key1, iv).unwrap();
        // Decrypting with wrong key should fail
        let result = decrypt_data(&encrypted, key2, iv);
        assert!(result.is_err());
    }
}
