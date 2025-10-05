# encrypted_include

Include AES encrypted binary assets into Rust projects at compile time.

## Features

- AES-256-CBC encryption/decryption
- Simple API for encrypting and decrypting data
- Compile-time inclusion of encrypted assets
- PKCS7 padding support

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
encrypted_include = "0.1"
```

### Basic Example

```rust
use encrypted_include::{encrypt_data, decrypt_data};

fn main() {
    // Define a 32-byte key for AES-256 and a 16-byte IV
    let key = b"my_secret_key_32_bytes_long!!!!!";
    let iv = b"my_16_byte_iv!!!";

    // Original data to encrypt
    let data = b"This is secret data!";

    // Encrypt the data
    let encrypted = encrypt_data(data, key, iv).expect("Encryption failed");

    // Decrypt the data
    let decrypted = decrypt_data(&encrypted, key, iv).expect("Decryption failed");

    assert_eq!(data, decrypted.as_slice());
}
```

### Including Encrypted Files

Use the `encrypted_include_bytes!` macro to include encrypted file contents:

```rust
use encrypted_include::encrypted_include_bytes;

const ENCRYPTED_DATA: &[u8] = encrypted_include_bytes!(
    "path/to/file.txt",
    "0123456789abcdef0123456789abcdef",
    "0123456789abcdef"
);
```

## License

MIT OR Apache-2.0
