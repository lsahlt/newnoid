use aes_gcm::{aead::{Aead, KeyInit, OsRng}, Aes256Gcm, Key, Nonce};
use rand::RngCore;

use crate::crypto::kyber;

/// Encrypts a message using a Kyber-shared secret (AES-256-GCM)
pub fn send_message(message: &[u8], receiver_pk: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    // Step 1: Encapsulate with Kyber
    let (kyber_ct, shared_secret) = kyber::encapsulate(receiver_pk);

    // Step 2: Prepare AES key from shared secret
    let key = Key::<Aes256Gcm>::from_slice(&shared_secret[0..32]); // 256-bit
    let cipher = Aes256Gcm::new(key);

    // Step 3: Random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Step 4: Encrypt
    let ciphertext = cipher.encrypt(nonce, message).expect("encryption failed");

    // Return: AES ciphertext, nonce, Kyber ciphertext (NOT shared secret!)
    (ciphertext, nonce_bytes.to_vec(), kyber_ct)
}
