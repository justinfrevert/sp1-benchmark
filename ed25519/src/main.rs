

#![no_main]

use program_primitives::Ed25519Input;
use ed25519_consensus::{Signature, VerificationKey};

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let input: Ed25519Input = sp1_zkvm::io::read();

    assert_eq!(input.pubkey_bytes.len(), input.message_bytes.len());
    assert_eq!(input.message_bytes.len(), input.signature_bytes.len());

    for i in 0..input.pubkey_bytes.len() {
        let pk_bytes: &[u8] = &input.pubkey_bytes[i];
        let sig_bytes: &[u8] = &input.signature_bytes[i];
        let msg: &[u8] = &input.message_bytes[i];

        // Convert to array types expected by `ed25519_consensus`
        let pubkey = VerificationKey::try_from(
            <[u8; 32]>::try_from(pk_bytes).expect("Invalid pubkey length")
        ).expect("Invalid pubkey");

        let signature = Signature::from(
            <[u8; 64]>::try_from(sig_bytes).expect("Invalid signature length")
        );

        if pubkey.verify(&signature, msg).is_err() {
            panic!("Failed to verify signature at index {i}");
        }

    }

    sp1_zkvm::io::commit(&(input.pubkey_bytes.len() as u32));
}
