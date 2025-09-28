use aes_gcm::{aead::Aead, Aes256Gcm, Key, Nonce, KeyInit};

use crate::crypto::kyber;

/// Decrypt a message using Kyber secret key + AES-256-GCM
pub fn receive_message(ciphertext: &[u8], nonce: &[u8], kyber_ct: &[u8], sk: &[u8]) -> Vec<u8> {
    // Step 1: Decapsulate shared secret
    let shared_secret = kyber::decapsulate(kyber_ct, sk);

    // Step 2: Build AES key
    let key = Key::<Aes256Gcm>::from_slice(&shared_secret[0..32]);
    let cipher = Aes256Gcm::new(key);

    // Step 3: Decrypt
    let nonce_obj = Nonce::from_slice(nonce);
    cipher.decrypt(nonce_obj, ciphertext).expect("decryption failed")
}

