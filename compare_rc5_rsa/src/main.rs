extern crate openssl;

use std::time::Instant;
use rc5_algo::{RC5, RC5WordSize};
use clap::Parser;
use openssl::rsa::{Rsa, Padding};

#[derive(Parser, Debug,)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// File path to read data or cypher
    #[arg(short, long)]
    data_path: String,

    /// Number of iterations
    #[arg(short, long, default_value_t = 10)]
    iterations: usize,
    
    #[arg(short, long, default_value_t = 32)]
    word_size: u8,

    #[arg(short, long, default_value_t = 16)]
    rounds: u8,

    /// Number of octets in key
    #[arg(short, long, default_value_t = 8)]
    bytes_key: u8,
}

fn main() {
    let cli = Cli::parse();
    let data = std::fs::read(cli.data_path).expect("Failed to read test data");
    let word_size = match cli.word_size {
        16 => RC5WordSize::Bits16,
        32 => RC5WordSize::Bits32,
        64 => RC5WordSize::Bits64,
        _ => unreachable!("Wrong word size provided: Accept only: 16, 32, 64."),
    };
    let rc5 = RC5::new(word_size, cli.rounds, cli.bytes_key);
    let rc5_key = rc5.generate_key(b"SomeTextPhraseForKey");
    let rsa_keypair = Rsa::generate(2048)
        .expect("Failed to generate rsa keys");
    let rsa_private_key_pem = rsa_keypair.private_key_to_pem()
        .expect("Failed to generate private key pem");
    let rsa_pubkey_pem = rsa_keypair.public_key_to_pem_pkcs1()
        .expect("Failed to generate public key pem");
    let rsa_pubkey = Rsa::public_key_from_pem_pkcs1(&rsa_pubkey_pem)
        .expect("Failed to generate public key");
    let rsa_private_key = Rsa::private_key_from_pem(&rsa_private_key_pem)
        .expect("Failed to generate private key");

    let rc5_cypher: Vec<u8> = rc5.encrypt_cbc_pad(&data, &rc5_key).0;
    let mut rsa_cypher = vec![0; rsa_pubkey.size() as usize];
    let mut rsa_decrypted = vec![0; rsa_keypair.size() as usize];
    
    let mut rc5_enc_time = 0u128;
    let mut rsa_enc_time = 0u128;

    let mut rc5_dec_time = 0u128;
    let mut rsa_dec_time = 0u128;

    for _ in 0..cli.iterations {
        let start = Instant::now();
        let _ = rc5.encrypt_cbc_pad(&data, &rc5_key);
        rc5_enc_time += Instant::now().duration_since(start).as_micros();

        let start = Instant::now();
        let _ = rc5.decrypt_cbc_pad(&rc5_cypher, &rc5_key);
        rc5_dec_time += Instant::now().duration_since(start).as_micros();

        let start = Instant::now();
        let _ = rsa_pubkey.public_encrypt(&data, &mut rsa_cypher, Padding::PKCS1)
            .expect("RSA encryption failed");
        rsa_enc_time += Instant::now().duration_since(start).as_micros();

        let start = Instant::now();
        let _ = rsa_private_key.private_decrypt(&rsa_cypher, &mut rsa_decrypted, Padding::PKCS1)
            .expect("RSA decryption failed");
        rsa_dec_time += Instant::now().duration_since(start).as_micros();
    }

    println!(r"
        RC5 ------------------------
        Total time: {tt} us
        Encryption total: {e_tt} us
        Decryption total: {d_tt} us
    ",
        tt = rc5_enc_time + rc5_dec_time,
        e_tt = rc5_enc_time,
        d_tt = rc5_dec_time,
    );

    println!(r"
        RSA ------------------------
        Total time: {tt} us
        Encryption total: {e_tt} us
        Decryption total: {d_tt} us
    ",
        tt = rsa_enc_time + rsa_dec_time,
        e_tt = rsa_enc_time,
        d_tt = rsa_dec_time,
    );
 }
