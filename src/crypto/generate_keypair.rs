use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{PublicKey as _, SecretKey as _};

pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = kyber1024::keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

