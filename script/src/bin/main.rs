use clap::Parser;
use program_primitives::{EcdsaInput, Ed25519Input};
use rand_core::OsRng;
use rand_core::TryRngCore;
use sp1_sdk::{include_elf, EnvProver, ProverClient, SP1Stdin};
use std::time::Instant;

use k256::ecdsa::signature::Signer;
use k256::{
    ecdsa::{signature::Verifier, Signature, SigningKey, VerifyingKey},
    EncodedPoint,
};

use ed25519_consensus::{
    Signature as Ed25519Signature, SigningKey as Ed25519SigningKey,
    VerificationKey as Ed25519VerifyingKey,
};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci-program");
pub const ED25519_ELF: &[u8] = include_elf!("ed25519-program");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    sig_amount: u32,

    // prove ed255109 signatures instead of ecdsa
    #[arg(long)]
    ed25519: bool,

    /// Use PLONK instead of default Groth16
    #[arg(long)]
    plonk: bool,
}

fn generate_ecdsa_inputs(count: usize) -> EcdsaInput {
    let mut pubkey_bytes = Vec::new();
    let mut message_bytes = Vec::new();
    let mut signature_bytes = Vec::new();

    for _ in 0..count {
        let mut sk_bytes = [0u8; 32];
        OsRng.try_fill_bytes(&mut sk_bytes);

        let signing_key = SigningKey::from_slice(&sk_bytes).unwrap();
        let verify_key = signing_key.verifying_key();

        let msg = b"hello world".to_vec(); // or random if you prefer
        let sig: Signature = signing_key.sign(&msg);

        pubkey_bytes.push(verify_key.to_sec1_bytes().into());
        message_bytes.push(msg);
        signature_bytes.push(sig.to_bytes().to_vec());
    }

    EcdsaInput {
        pubkey_bytes,
        message_bytes,
        signature_bytes,
    }
}

fn generate_ed25519_inputs(count: usize) -> Ed25519Input {
    let mut pubkey_bytes = Vec::new();
    let mut message_bytes = Vec::new();
    let mut signature_bytes = Vec::new();

    for _ in 0..count {
        let mut sk_bytes = [0u8; 32];
        OsRng.try_fill_bytes(&mut sk_bytes);

        // let signing_key = Ed25519SigningKey::from_bytes(&sk_bytes);

        let signing_key = Ed25519SigningKey::try_from(
            <[u8; 32]>::try_from(sk_bytes).expect("Invalid pubkey length"),
        )
        .expect("Invalid signingkey");

        let verifying_key = Ed25519VerifyingKey::from(&signing_key);

        let msg = b"hello world".to_vec();
        let sig: Ed25519Signature = signing_key.sign(&msg);

        pubkey_bytes.push(verifying_key.to_bytes().to_vec());
        message_bytes.push(msg);
        signature_bytes.push(sig.to_bytes().to_vec());
    }

    Ed25519Input {
        pubkey_bytes,
        message_bytes,
        signature_bytes,
    }
}

fn prove_with_selected_scheme(
    client: &EnvProver,
    pk: &sp1_sdk::SP1ProvingKey,
    stdin: &SP1Stdin,
    use_plonk: bool,
) -> Result<sp1_sdk::SP1ProofWithPublicValues, Box<dyn std::error::Error>> {
    if use_plonk {
        Ok(client.prove(pk, stdin).plonk().run()?)
    } else {
        Ok(client.prove(pk, stdin).groth16().run()?)
    }
}

fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse the command line arguments.
    let args = Args::parse();

    let client = ProverClient::from_env();

    if args.ed25519 {
        println!("Using Ed25519 precompile...");
        let input = generate_ed25519_inputs(args.sig_amount as usize);
        let mut stdin = SP1Stdin::new();
        stdin.write(&input);

        let (pk, vk) = client.setup(ED25519_ELF);

        let start = Instant::now();
        println!("Proving..");
        let proof =
            prove_with_selected_scheme(&client, &pk, &stdin, args.plonk).expect("failed to prove");
        let proving_time = start.elapsed();

        let verify_start = Instant::now();
        client.verify(&proof, &vk).expect("failed to verify");
        let verify_time = verify_start.elapsed();

        println!("Ed25519 Proof time:   {:?}", proving_time);
        println!("Ed25519 Verify time: {:?}", verify_time);
    } else {
        println!("Using ECDSA (k256)...");
        let input = generate_ecdsa_inputs(args.sig_amount as usize);
        let mut stdin = SP1Stdin::new();
        stdin.write(&input);

        let (pk, vk) = client.setup(FIBONACCI_ELF);

        let start = Instant::now();
        println!("Proving..");
        let proof =
            prove_with_selected_scheme(&client, &pk, &stdin, args.plonk).expect("failed to prove");
        let proving_time = start.elapsed();

        let verify_start = Instant::now();
        client.verify(&proof, &vk).expect("failed to verify");
        let verify_time = verify_start.elapsed();

        println!("ECDSA Proof time:   {:?}", proving_time);
        println!("ECDSA Verify time: {:?}", verify_time);
    }
}
