use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes256;
use base64::Engine;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};

use crate::error::{Error, Result};

type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// AES-256-ECB decrypt with PKCS7 unpadding.
pub fn aes_ecb_decrypt(key: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(Error::Other(format!(
            "depot key must be 32 bytes, got {}",
            key.len()
        )));
    }

    if input.len() % 16 != 0 {
        return Err(Error::Other(format!(
            "encrypted data length {} not a multiple of 16",
            input.len()
        )));
    }

    let cipher =
        Aes256::new_from_slice(key).map_err(|e| Error::Other(format!("AES key init: {}", e)))?;

    let mut output = input.to_vec();
    for block in output.chunks_exact_mut(16) {
        cipher.decrypt_block(aes::Block::from_mut_slice(block));
    }

    // Remove PKCS7 padding
    if let Some(&pad_len) = output.last() {
        let pad_len = pad_len as usize;
        if pad_len > 0 && pad_len <= 16 && output.len() >= pad_len {
            if output[output.len() - pad_len..]
                .iter()
                .all(|&b| b == pad_len as u8)
            {
                output.truncate(output.len() - pad_len);
            }
        }
    }

    Ok(output)
}

/// AES-256-CBC decrypt with PKCS7 unpadding.
pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(Error::Other(format!(
            "AES-CBC key must be 32 bytes, got {}",
            key.len()
        )));
    }
    if iv.len() != 16 {
        return Err(Error::Other(format!(
            "AES-CBC IV must be 16 bytes, got {}",
            iv.len()
        )));
    }

    let mut buf = input.to_vec();
    let decryptor = Aes256CbcDec::new_from_slices(key, iv)
        .map_err(|e| Error::Other(format!("AES-CBC init: {}", e)))?;

    // decrypt_padded_mut already decrypts in place inside `buf`, returning
    // a sub-slice of it with the PKCS7 padding excluded -- truncate `buf`
    // to that length and return it directly instead of copying the
    // plaintext out into a second, brand-new allocation. The in-place API
    // was already being used correctly; the previous `plaintext.to_vec()`
    // just threw that away with a redundant full-buffer copy on every
    // chunk decrypted.
    let plaintext_len = decryptor
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|e| Error::Other(format!("AES-CBC decrypt: {}", e)))?
        .len();
    buf.truncate(plaintext_len);

    Ok(buf)
}

/// Decrypt an encrypted manifest filename.
///
/// SteamKit2 `DepotManifest.cs` algorithm:
/// 1. Base64 decode the filename string
/// 2. ECB-decrypt the first 16 bytes to get the IV
/// 3. CBC-decrypt the remainder using that IV + PKCS7 padding
/// 4. Strip trailing null bytes
/// 5. Interpret as UTF-8
pub fn decrypt_filename(key: &[u8], encrypted_b64: &str) -> Result<String> {
    // Filenames may contain newlines/whitespace in the base64 encoding
    let cleaned: String = encrypted_b64
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let encrypted = base64::engine::general_purpose::STANDARD
        .decode(&cleaned)
        .map_err(|e| Error::Other(format!("filename base64 decode: {}", e)))?;

    if encrypted.len() < 32 {
        return Err(Error::Other(format!(
            "encrypted filename too short ({} bytes, need at least 32)",
            encrypted.len()
        )));
    }

    // First 16 bytes: ECB-decrypt to get the IV
    let iv = aes_ecb_decrypt_block(key, &encrypted[..16])?;

    // Remainder: CBC-decrypt with that IV
    let plaintext = aes_cbc_decrypt(key, &iv, &encrypted[16..])?;

    // Strip trailing null bytes
    let end = plaintext
        .iter()
        .rposition(|&b| b != 0)
        .map(|i| i + 1)
        .unwrap_or(0);

    String::from_utf8(plaintext[..end].to_vec())
        .map_err(|e| Error::Other(format!("filename UTF-8: {}", e)))
}

/// SteamKit2-compatible symmetric decrypt.
///
/// Input format: first 16 bytes are the AES-ECB-encrypted IV, remainder is
/// AES-256-CBC encrypted with PKCS7 padding. This is used for chunk data
/// and encrypted filenames.
pub fn symmetric_decrypt(key: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    if input.len() < 32 {
        return Err(Error::Other(format!(
            "encrypted data too short ({} bytes, need at least 32)",
            input.len()
        )));
    }

    let iv = aes_ecb_decrypt_block(key, &input[..16])?;
    aes_cbc_decrypt(key, &iv, &input[16..])
}

/// ECB-decrypt a single 16-byte block (no padding removal).
fn aes_ecb_decrypt_block(key: &[u8], block: &[u8]) -> Result<Vec<u8>> {
    let cipher =
        Aes256::new_from_slice(key).map_err(|e| Error::Other(format!("AES key init: {}", e)))?;

    let mut output = [0u8; 16];
    output.copy_from_slice(block);
    cipher.decrypt_block(aes::Block::from_mut_slice(&mut output));
    Ok(output.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbc::cipher::BlockEncryptMut;

    type Aes256CbcEnc = cbc::Encryptor<Aes256>;

    /// Round-trips real plaintext through encrypt-then-aes_cbc_decrypt --
    /// specifically to confirm the truncate-instead-of-copy change above
    /// still returns exactly the original plaintext, not just "doesn't
    /// panic". Covers both a size that needs multiple padding bytes and
    /// one that lands on an exact block boundary (a full 16-byte block of
    /// pure padding), since those exercise different PKCS7 edge cases.
    fn roundtrip(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) {
        let encryptor = Aes256CbcEnc::new_from_slices(key, iv).unwrap();
        let mut buf = vec![0u8; plaintext.len() + 16];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        let ciphertext_len = encryptor
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .unwrap()
            .len();
        buf.truncate(ciphertext_len);

        let decrypted = aes_cbc_decrypt(key, iv, &buf).expect("decrypt failed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes_cbc_decrypt_roundtrips() {
        let key = [0x42u8; 32];
        let iv = [0x24u8; 16];

        roundtrip(&key, &iv, b"a short chunk of plaintext");
        roundtrip(&key, &iv, &[0u8; 16]); // exact block boundary -- full pad block
        roundtrip(&key, &iv, &[0xABu8; 1024]); // larger, multi-block
        roundtrip(&key, &iv, b"");
    }
}
