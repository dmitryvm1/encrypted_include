# encrypted_include

[![Crates.io](https://img.shields.io/crates/v/encrypted_include.svg)](https://crates.io/crates/encrypted_include)
[![Documentation](https://docs.rs/encrypted_include/badge.svg)](https://docs.rs/encrypted_include)

Include AES-256-GCM encrypted binary assets into Rust projects at compile time.

## Overview

`encrypted_include` provides a compile-time macro similar to `include_bytes!` that embeds static files into your binary in an encrypted form using AES-256-GCM. This adds a layer of protection against casual reverse engineering and static inspection while maintaining the convenience of embedding assets directly in code.

## Features

- 🔒 **Compile-time encryption** using AES-256-GCM
- 🔑 **Simple API** similar to `include_bytes!`
- 🛡️ **Authenticated encryption** with built-in tamper detection
- 🎲 **Automatic nonce generation** for each inclusion
- ⚡ **Zero runtime overhead** for encryption (only decryption at runtime)

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
encrypted_include = "0.1.0"
```

## Usage

### Basic Example

```rust
use encrypted_include::{include_encrypted, decrypt};

// Define your 32-byte encryption key
const KEY: &[u8; 32] = b"my-secret-encryption-key-32b!!!!";

// Include and encrypt a file at compile time
const ENCRYPTED_DATA: &[u8] = include_encrypted!("path/to/secret.txt", b"my-secret-encryption-key-32b!!!!");

fn main() {
    // Decrypt at runtime
    let decrypted = decrypt(ENCRYPTED_DATA, KEY)
        .expect("Failed to decrypt");
    
    println!("Content: {}", String::from_utf8_lossy(&decrypted));
}
```

### Working with Binary Data

```rust
use encrypted_include::{include_encrypted, decrypt};

const KEY: &[u8; 32] = b"my-secret-encryption-key-32b!!!!";
const ENCRYPTED_IMAGE: &[u8] = include_encrypted!("assets/image.png", b"my-secret-encryption-key-32b!!!!");

fn main() {
    let image_data = decrypt(ENCRYPTED_IMAGE, KEY)
        .expect("Failed to decrypt image");
    
    // Use image_data...
}
```

## API Reference

### `include_encrypted!` Macro

```rust
include_encrypted!(path: &str, key: &[u8; 32]) -> &'static [u8]
```

Encrypts and embeds a file at compile time.

**Parameters:**
- `path`: String literal pointing to the file to embed (relative to `CARGO_MANIFEST_DIR`)
- `key`: Byte string literal of exactly 32 bytes for AES-256

**Returns:**
- A static byte slice containing `[nonce (12 bytes) || ciphertext]`

**Compile-time Errors:**
- If the key is not exactly 32 bytes
- If the file cannot be read
- If encryption fails

### `decrypt` Function

```rust
fn decrypt(data: &[u8], key: &[u8]) -> Result<Vec<u8>, DecryptError>
```

Decrypts data that was encrypted using `include_encrypted!`.

**Parameters:**
- `data`: The encrypted data (nonce + ciphertext)
- `key`: The 32-byte encryption key

**Returns:**
- `Ok(Vec<u8>)`: The decrypted plaintext
- `Err(DecryptError)`: If decryption fails

**Runtime Errors:**
- `DecryptError::DataTooShort`: Data is too short to contain a nonce
- `DecryptError::InvalidKeyLength`: Key is not 32 bytes
- `DecryptError::DecryptionFailed`: Wrong key, corrupted data, or tampered ciphertext

## Security Considerations

### What This Crate Provides

✅ **Obfuscation**: Makes casual inspection of embedded files more difficult  
✅ **Tamper Detection**: AES-GCM authentication prevents undetected modifications  
✅ **Unique Ciphertexts**: Random nonces ensure different ciphertexts even for identical files

### What This Crate Does NOT Provide

❌ **True Secret Protection**: Keys are embedded in the binary and can be extracted by determined attackers  
❌ **Protection Against Reverse Engineering**: Skilled reverse engineers can recover keys from binaries  
❌ **Runtime Key Management**: Keys must be known at compile time

### Intended Use Cases

- Protecting configuration files from casual inspection
- Embedding proprietary templates or data
- Adding a basic layer of protection to embedded assets
- Obscuring file formats and content from static analysis tools

### NOT Recommended For

- Storing API keys or passwords
- Protecting high-value secrets
- Compliance with strict security requirements
- Defense against determined adversaries

### Best Practices

1. **Key Management**: Consider deriving keys from build-time environment variables
2. **Key Rotation**: Different keys for different builds or deployments
3. **Defense in Depth**: Use this as one layer among multiple security measures
4. **Assume Compromise**: Never rely solely on this for critical security

## How It Works

### Compile-Time Process

1. The `include_encrypted!` macro reads the specified file
2. Validates that the key is exactly 32 bytes
3. Generates a random 12-byte nonce
4. Encrypts the file contents using AES-256-GCM
5. Combines nonce and ciphertext: `[nonce || ciphertext]`
6. Embeds the result as a static byte array in your binary

### Runtime Process

1. The `decrypt` function receives the encrypted data and key
2. Splits the first 12 bytes as the nonce
3. Uses the key and nonce to decrypt with AES-256-GCM
4. Returns the plaintext or an error if decryption fails

## Examples

Run the included example:

```bash
cargo run --example basic_usage
```

## Testing

Run the test suite:

```bash
cargo test
```

## Alternatives

- **[`include_bytes!`](https://doc.rust-lang.org/std/macro.include_bytes.html)**: Standard library macro for embedding files without encryption
- **[`include-flate`](https://crates.io/crates/include-flate)**: Compresses embedded files but doesn't encrypt
- **[`rust-embed`](https://crates.io/crates/rust-embed)**: Asset bundling without encryption
- **[`const-crypt`](https://crates.io/crates/const-crypt)**: String obfuscation, not for arbitrary files

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Future Enhancements

- Support for additional ciphers (ChaCha20-Poly1305)
- `include_encrypted_str!` macro for UTF-8 assets
- Optional runtime-provided keys
- Key rotation tooling
