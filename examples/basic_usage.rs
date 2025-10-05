use encrypted_include::{decrypt_data, encrypt_data};

fn main() {
    // Define a 32-byte key for AES-256 and a 16-byte IV
    let key = b"my_secret_key_32_bytes_long!!!!!"; // 32 bytes
    let iv = b"my_16_byte_iv!!!"; // 16 bytes

    // Original data to encrypt
    let original_data = b"This is secret data that will be encrypted!";

    println!("Original data: {:?}", String::from_utf8_lossy(original_data));
    println!("Original data length: {} bytes", original_data.len());

    // Encrypt the data
    let encrypted = encrypt_data(original_data, key, iv).expect("Encryption failed");
    println!("\nEncrypted data length: {} bytes", encrypted.len());
    println!("Encrypted data (hex): {}", hex::encode(&encrypted));

    // Decrypt the data
    let decrypted = decrypt_data(&encrypted, key, iv).expect("Decryption failed");
    println!("\nDecrypted data: {:?}", String::from_utf8_lossy(&decrypted));
    println!("Decrypted data length: {} bytes", decrypted.len());

    // Verify the round-trip worked
    assert_eq!(original_data, decrypted.as_slice());
    println!("\n✓ Round-trip encryption/decryption successful!");
}
