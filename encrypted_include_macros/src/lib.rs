use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, LitByteStr, LitStr};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use rand::Rng;

/// Parse macro arguments: path and key
struct IncludeEncryptedArgs {
    path: String,
    key: Vec<u8>,
}

impl syn::parse::Parse for IncludeEncryptedArgs {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        // Parse the path (string literal)
        let path_lit: LitStr = input.parse()?;
        let path = path_lit.value();

        // Parse the comma
        let _: syn::Token![,] = input.parse()?;

        // Parse the key (byte string literal)
        let key_lit: LitByteStr = input.parse()?;
        let key = key_lit.value();

        Ok(IncludeEncryptedArgs { path, key })
    }
}

/// Compile-time macro to include and encrypt a file
/// 
/// # Example
/// 
/// ```ignore
/// const DATA: &[u8] = include_encrypted!("assets/secret.txt", b"32-byte-supersecret-key1234567");
/// ```
#[proc_macro]
pub fn include_encrypted(input: TokenStream) -> TokenStream {
    let args = parse_macro_input!(input as IncludeEncryptedArgs);

    // Validate key length
    if args.key.len() != 32 {
        return syn::Error::new(
            proc_macro2::Span::call_site(),
            format!("Key must be exactly 32 bytes for AES-256, got {} bytes", args.key.len()),
        )
        .to_compile_error()
        .into();
    }

    // Read the file at compile time
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR not set");
    let file_path = std::path::Path::new(&manifest_dir).join(&args.path);
    
    let file_contents = match std::fs::read(&file_path) {
        Ok(contents) => contents,
        Err(e) => {
            return syn::Error::new(
                proc_macro2::Span::call_site(),
                format!("Failed to read file '{}': {}", file_path.display(), e),
            )
            .to_compile_error()
            .into();
        }
    };

    // Generate a random 12-byte nonce
    let nonce_bytes: [u8; 12] = rand::thread_rng().gen();
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Create cipher instance
    let cipher = Aes256Gcm::new_from_slice(&args.key)
        .expect("Failed to create cipher");

    // Encrypt the file contents
    let ciphertext = match cipher.encrypt(nonce, file_contents.as_ref()) {
        Ok(ct) => ct,
        Err(e) => {
            return syn::Error::new(
                proc_macro2::Span::call_site(),
                format!("Encryption failed: {}", e),
            )
            .to_compile_error()
            .into();
        }
    };

    // Combine nonce and ciphertext: [nonce || ciphertext]
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);

    // Generate the output token stream as a byte array literal
    let bytes = result.as_slice();
    let expanded = quote! {
        &[#(#bytes),*]
    };

    expanded.into()
}
