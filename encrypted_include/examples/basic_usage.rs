use encrypted_include::{include_encrypted, decrypt};

// The encryption key - in a real application, you might derive this from
// a build-time environment variable or other source
const KEY: &[u8; 32] = b"my-secret-encryption-key-32b!!!!";

// Include and encrypt the file at compile time
const ENCRYPTED_SECRET: &[u8] = include_encrypted!("examples/assets/secret.txt", b"my-secret-encryption-key-32b!!!!");

fn main() {
    println!("=== Encrypted Include Example ===\n");

    // Show the encrypted data
    println!("Encrypted data length: {} bytes", ENCRYPTED_SECRET.len());
    println!("First 20 bytes (hex): {:02x?}\n", &ENCRYPTED_SECRET[..20.min(ENCRYPTED_SECRET.len())]);

    // Decrypt at runtime
    match decrypt(ENCRYPTED_SECRET, KEY) {
        Ok(plaintext) => {
            println!("Successfully decrypted!");
            println!("\nDecrypted content:");
            println!("---");
            println!("{}", String::from_utf8_lossy(&plaintext));
            println!("---");
        }
        Err(e) => {
            eprintln!("Failed to decrypt: {}", e);
            std::process::exit(1);
        }
    }

    // Demonstrate wrong key failure
    println!("\nAttempting decryption with wrong key...");
    let wrong_key = b"wrong-key-that-wont-work-32bytes";
    match decrypt(ENCRYPTED_SECRET, wrong_key) {
        Ok(_) => {
            println!("Unexpected: Decryption succeeded with wrong key!");
        }
        Err(e) => {
            println!("Expected failure: {}", e);
        }
    }
}
