//! An end-to-end example of using the SP1 SDK to generate a proof of a program that can be executed
//! or have a core proof generated.
//!
//! You can run this script using the following command:
//! ```shell
//! RUST_LOG=info cargo run --release -- --execute
//! ```
//! or
//! ```shell
//! RUST_LOG=info cargo run --release -- --prove
//! ```

use clap::Parser;
use program_primitives::EcdsaInput;
use rand_core::OsRng;
use rand_core::TryRngCore;
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use std::time::Instant;

use k256::ecdsa::signature::Signer;
use k256::{
    ecdsa::{signature::Verifier, Signature, SigningKey, VerifyingKey},
    EncodedPoint,
};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const FIBONACCI_ELF: &[u8] = include_elf!("fibonacci-program");

/// The arguments for the command.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    execute: bool,

    #[arg(long)]
    prove: bool,

    #[arg(long, default_value = "20")]
    n: u32,
}

fn generate_inputs(count: usize) -> EcdsaInput {
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


fn main() {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse the command line arguments.
    let args = Args::parse();

    if args.execute == args.prove {
        eprintln!("Error: You must specify either --execute or --prove");
        std::process::exit(1);
    }

    let client = ProverClient::from_env();

    let mut stdin = SP1Stdin::new();
    let input = generate_inputs(500);
    stdin.write(&input);

    let mut stdin = SP1Stdin::new();
    stdin.write(&input);

    if args.execute {
        println!("Only for proving");
    } else {
        // Setup the program for proving.
        println!("Generating proving and verification keys...");
        let (pk, vk) = client.setup(FIBONACCI_ELF);

        println!("Starting proof generation...");
        let start = Instant::now();
        let proof = client
            .prove(&pk, &stdin)
            .run()
            .expect("failed to generate proof");
        let proving_time = start.elapsed();
        println!("Proof generated in {:.2?}", proving_time);

        println!("Starting proof verification...");
        let verify_start = Instant::now();
        client.verify(&proof, &vk).expect("failed to verify proof");
        let verify_time = verify_start.elapsed();
        println!("Proof verified in {:.2?}", verify_time);
    }
}
