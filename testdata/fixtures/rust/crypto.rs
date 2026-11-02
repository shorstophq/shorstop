// Fixture: Rust crates, plus near-misses.
use ed25519_dalek::SigningKey;
use p256::ecdsa::{Signature, SigningKey as EcKey};
use ml_kem::{KemCore, MlKem768};
use rsa::RsaPrivateKey;

fn run() {
    let key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let digest = md5::compute(b"abc");

    // Near-misses:
    let ok = sha2::Sha256::new();
}
