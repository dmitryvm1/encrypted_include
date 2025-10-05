use encrypted_include::{include_encrypted, decrypt};

const KEY: &[u8; 32] = b"32-byte-supersecret-key123456789";

#[test]
fn test_include_encrypted_text_file() {
    // Include and encrypt the test file at compile time
    const ENCRYPTED_DATA: &[u8] = include_encrypted!("tests/assets/test_file.txt", b"32-byte-supersecret-key123456789");

    // Decrypt at runtime
    let decrypted = decrypt(ENCRYPTED_DATA, KEY)
        .expect("Failed to decrypt data");

    // Convert to string and verify content
    let content = String::from_utf8(decrypted)
        .expect("Failed to convert to UTF-8");

    assert!(content.contains("Hello, World!"));
    assert!(content.contains("multiple lines"));
    assert!(content.contains("123, !@#$%^&*()"));
}

#[test]
fn test_decrypt_with_wrong_key() {
    const ENCRYPTED_DATA: &[u8] = include_encrypted!("tests/assets/test_file.txt", b"32-byte-supersecret-key123456789");

    // Try to decrypt with a different key
    let wrong_key = b"different-key-32bytes-long!!!!!";
    let result = decrypt(ENCRYPTED_DATA, wrong_key);

    // Should fail
    assert!(result.is_err());
}

#[test]
fn test_multiple_inclusions_same_file() {
    // Include the same file twice with the same key
    const ENCRYPTED_DATA_1: &[u8] = include_encrypted!("tests/assets/test_file.txt", b"32-byte-supersecret-key123456789");
    const ENCRYPTED_DATA_2: &[u8] = include_encrypted!("tests/assets/test_file.txt", b"32-byte-supersecret-key123456789");

    // Both should decrypt successfully
    let decrypted_1 = decrypt(ENCRYPTED_DATA_1, KEY)
        .expect("Failed to decrypt data 1");
    let decrypted_2 = decrypt(ENCRYPTED_DATA_2, KEY)
        .expect("Failed to decrypt data 2");

    // Both should have the same content
    assert_eq!(decrypted_1, decrypted_2);

    // But the encrypted data should be different (due to different nonces)
    assert_ne!(ENCRYPTED_DATA_1, ENCRYPTED_DATA_2);
}
