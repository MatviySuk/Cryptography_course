extern crate openssl;

use clap::{Args, Parser, Subcommand};
use openssl::dsa::Dsa;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::{Signer, Verifier};
use std::fs;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    operation: Operation,
}

#[derive(Subcommand, Debug)]
enum Operation {
    Keys(KeysArgs),
    Sign(CryptoArgs),
    Verify(CryptoArgs),
}

#[derive(Args, Debug)]
struct KeysArgs {
    /// Keys name
    #[arg(short, long)]
    keys_name: String,

    /// Save path
    #[arg(short, long, default_value = "")]
    save_path: String,

    #[arg(short, long, default_value_t = 2048)]
    block_size: u32,
}

#[derive(Args, Debug)]
struct CryptoArgs {
    /// File path to read data or cypher
    #[arg(short, long)]
    data_path: String,

    /// Path to signature file
    #[arg(short, long)]
    signature_path: String,

    /// File path to save generated keys
    #[arg(short, long, default_value = "")]
    keys_path: String,
}

fn main() {
    let cli = Cli::parse();

    match cli.operation {
        Operation::Keys(args) => {
            if !(args.block_size != 0 && (args.block_size & (args.block_size - 1)) == 0) {
                panic!(
                    "Block size should be 2 in power of n. Current value is: {}",
                    args.block_size
                );
            }

            let dsa = Dsa::generate(args.block_size).expect("Failed to generate dsa keys!");
            let private_key = dsa
                .private_key_to_pem()
                .expect("Failed to generate private pem key!");
            let public_key = dsa
                .public_key_to_pem()
                .expect("Failed to generate public pem key!");

            fs::write(format!("{}_key.pem", args.keys_name), private_key)
                .expect("Failed to save private pem key to file!");
            fs::write(format!("{}_key.pem.pub", args.keys_name), public_key)
                .expect("Failed to save public pem key to file!");
        }
        Operation::Sign(args) => {
            let data = fs::read(args.data_path).expect("Unable to read data from the file!");
            let pem_key_data = fs::read(args.keys_path).expect("Unable to read key from the file!");

            let private_key = PKey::private_key_from_pem(&pem_key_data)
                .expect("Failed to generate private key from pem file!");

            let mut signer = Signer::new(MessageDigest::sha1(), &private_key)
                .expect("Failed to create DSA signer!");

            signer
                .update(&data)
                .expect("Failed to pass data for verification!");

            let signature = hex::encode(
                signer
                    .sign_to_vec()
                    .expect("Failed to generate the signature!"),
            );

            fs::write(args.signature_path, signature)
                .expect("Failed to save data signature to file");
        }
        Operation::Verify(args) => {
            let data = fs::read(args.data_path).expect("Unable to read data from the file!");
            let signature = hex::decode(
                fs::read_to_string(args.signature_path)
                    .expect("Unable to read signature from the file!"),
            )
            .expect("Failed to decode hex string to bytes!");

            let pem_key_data = fs::read(args.keys_path).expect("Unable to read key from the file!");

            let public_key = PKey::public_key_from_pem(&pem_key_data)
                .expect("Failed to generate public key from pem file!");

            let mut verifier = Verifier::new(MessageDigest::sha1(), &public_key).unwrap();

            verifier
                .update(&data)
                .expect("Failed to pass data for verification!");

            match verifier
                .verify(&signature)
                .expect("Failed to verify the data by signature!")
            {
                true => println!("Successfully passed verification!"),
                false => println!("Failed verification!"),
            }
        }
    }
}
