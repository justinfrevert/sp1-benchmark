use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct EcdsaInput {
    // pub pubkey_bytes: Vec<[u8; 33]>,
    pub pubkey_bytes: Vec<Vec<u8>>,
    pub message_bytes: Vec<Vec<u8>>,
    pub signature_bytes: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Ed25519Input {
    pub pubkey_bytes: Vec<Vec<u8>>,
    pub message_bytes: Vec<Vec<u8>>,
    pub signature_bytes: Vec<Vec<u8>>,
}