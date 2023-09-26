use rc5_algo::RC5WordSize;
use clap::Parser;
use std::fs;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Key phrase to encrypt or decrypt data
    #[arg(short, long)]
    key: String,

    /// Encrypt = 0 or decrypt = 1 operation
    #[arg(short, long)]
    operation: u8,

    /// File path to read data or cypher
    #[arg(short, long)]
    file_path: String,

    /// File path to save operation result
    #[arg(short, long, default_value = "rc5_result")]
    save_path: String,

    /// Number of rounds
    #[arg(short, long, default_value_t = 32)]
    word_size: u8,

    /// Number of rounds
    #[arg(short, long, default_value_t = 16)]
    rounds: u8,

    /// Number of octets in key
    #[arg(short, long, default_value_t = 8)]
    bytes_key: u8,
}

fn main() {
    let args = Args::parse();

    let word_size = match args.word_size {
        16 => RC5WordSize::Bits16,
        32 => RC5WordSize::Bits32,
        64 => RC5WordSize::Bits64,
        _ => unreachable!("Wrong word size provided: Accept only: 16, 32, 64."),
    };

    let rc5 = rc5_algo::RC5::new(word_size, args.rounds, args.bytes_key);
    let key = rc5.generate_key(args.key.as_bytes());
    let data = fs::read(args.file_path).expect("Unable to read data from file");

    match args.operation {
        0 => {
            let cypher = rc5.encrypt_cbc_pad(&data, &key);

            fs::write(args.save_path, cypher.0).expect("Failed to cypher text to file");
        }
        1 => {
            let decrypted = rc5.decrypt_cbc_pad(&data, &key);

            fs::write(args.save_path, decrypted.0)
                .expect("Failed to save decryption result to file");
        }
        _ => unreachable!("Wrong operation code"),
    }
}