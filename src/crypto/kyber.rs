use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _, Ciphertext as _, SharedSecret as _};

/// Encapsulate a shared secret using receiver's public key
/// Returns (kyber_ciphertext, shared_secret)
pub fn encapsulate(pk_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let pk_obj = kyber1024::PublicKey::from_bytes(pk_bytes).expect("Bad public key length");
    let (ct, ss) = kyber1024::encapsulate(&pk_obj);
    let ct_bytes = ct.as_bytes().to_vec();
    let ss_bytes = ss.as_bytes().to_vec();
    // IMPORTANT: The library returns (shared_secret, ciphertext) not (ciphertext, shared_secret)
    // So we need to swap: ct is actually shared_secret, and ss is actually ciphertext
    (ss_bytes, ct_bytes)
}

/// Decapsulate shared secret using receiver's secret key
pub fn decapsulate(ct_bytes: &[u8], sk_bytes: &[u8]) -> Vec<u8> {
    let ct_obj = kyber1024::Ciphertext::from_bytes(ct_bytes).expect("Bad ciphertext length");
    let sk_obj = kyber1024::SecretKey::from_bytes(sk_bytes).expect("Bad secret key length");
    let ss = kyber1024::decapsulate(&ct_obj, &sk_obj);
    ss.as_bytes().to_vec() // shared secret
}
