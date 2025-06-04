

#![no_main]

use k256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    EncodedPoint,
};

use program_primitives::EcdsaInput;

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let input: EcdsaInput = sp1_zkvm::io::read();

    assert_eq!(input.pubkey_bytes.len(), input.message_bytes.len());
    assert_eq!(input.message_bytes.len(), input.signature_bytes.len());

    for i in 0..input.pubkey_bytes.len() {
        let pubkey = VerifyingKey::from_sec1_bytes(&input.pubkey_bytes[i]).unwrap();

        let sig = Signature::from_slice(&input.signature_bytes[i]).unwrap();
        // New
        // let signature = Signature::from_slice(signature_bytes.as_ref()).unwrap();

        pubkey.verify(&input.message_bytes[i], &sig).expect("Signature verification failed");
    }

    sp1_zkvm::io::commit(&(input.pubkey_bytes.len() as u32));
}