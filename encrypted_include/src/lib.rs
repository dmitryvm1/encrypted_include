use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

// Re-export the proc macro
pub use encrypted_include_macros::include_encrypted;

/// Error type for decryption operations
#[derive(Debug)]
pub enum DecryptError {
    /// The provided data is too short to contain a nonce
    DataTooShort,
    /// The provided key has an invalid length (must be 32 bytes for AES-256)
    InvalidKeyLength,
    /// Decryption failed (wrong key, corrupted data, or tampered ciphertext)
    DecryptionFailed(String),
}

impl std::fmt::Display for DecryptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecryptError::DataTooShort => write!(f, "Data too short to contain nonce"),
            DecryptError::InvalidKeyLength => write!(f, "Key must be exactly 32 bytes for AES-256"),
            DecryptError::DecryptionFailed(msg) => write!(f, "Decryption failed: {}", msg),
        }
    }
}

impl std::error::Error for DecryptError {}

/// Decrypt data that was encrypted using `include_encrypted!`
///
/// The data format is: `[nonce (12 bytes) | ciphertext]`
///
/// # Arguments
///
/// * `data` - The encrypted data (nonce + ciphertext)
/// * `key` - The 32-byte AES-256 key used for encryption
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The decrypted plaintext
/// * `Err(DecryptError)` - If decryption fails
///
/// # Example
///
/// ```ignore
/// use encrypted_include::{include_encrypted, decrypt};
///
/// const DATA: &[u8] = include_encrypted!("assets/secret.txt", b"32-byte-supersecret-key1234567");
///
/// let decrypted = decrypt(DATA, b"32-byte-supersecret-key1234567")
///     .expect("failed to decrypt data");
/// println!("Content: {}", String::from_utf8_lossy(&decrypted));
/// ```
pub fn decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, DecryptError> {
    // Validate minimum data length (12 bytes for nonce + at least some ciphertext)
    if data.len() < 12 {
        return Err(DecryptError::DataTooShort);
    }

    // Validate key length
    if key.len() != 32 {
        return Err(DecryptError::InvalidKeyLength);
    }

    // Split nonce and ciphertext
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Create cipher instance
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| DecryptError::DecryptionFailed(format!("Failed to create cipher: {}", e)))?;

    // Decrypt
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| DecryptError::DecryptionFailed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_invalid_key_length() {
        let data = vec![0u8; 20];
        let key = b"short-key";
        let result = decrypt(&data, key);
        assert!(matches!(result, Err(DecryptError::InvalidKeyLength)));
    }

    #[test]
    fn test_decrypt_data_too_short() {
        let data = vec![0u8; 5];
        let key = b"32-byte-supersecret-key1234567";
        let result = decrypt(&data, key);
        assert!(matches!(result, Err(DecryptError::DataTooShort)));
    }
}
