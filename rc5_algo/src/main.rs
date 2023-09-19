use random::LCGRandom;
use std::time::SystemTime;

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
    #[arg(short, long, default_value_t = 16)]
    rounds: u8,

    /// Number of octets in key
     #[arg(short, long, default_value_t = 8)]
    bytes_key: u8
}

fn main() {
    let args = Args::parse();
    
    let rc5_32 = rc5_algo::RC5_32::new(args.rounds, args.bytes_key);
    let key_hash = md5_algo::compute(args.key.as_bytes().to_vec());

    let key = match args.bytes_key {
        8 => key_hash.0[8..].to_vec(),
        16 => key_hash.0.to_vec(),
        32 => [md5_algo::compute(key_hash.0.to_vec()).0, key_hash.0].concat(),
        _ => unreachable!("Incorrect octets number in key"),   
    };

    let data = fs::read(args.file_path).expect("Unable to read data from file");

    match args.operation {
        0 => {
            let seed = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Failed to generate seed")
                .as_nanos();
            let mut lcg_rand = LCGRandom::new(1103515245, 12345, 2147483647, seed as u32);

            let iv: [u8; 8] =
                ((lcg_rand.generate() as u64) | ((lcg_rand.generate() as u64) << 32)).to_le_bytes();

            let cypher = rc5_32.encrypt_cbc_pad(&iv, &data, &key);

            fs::write(args.save_path, cypher.0).expect("Failed to cypher text to file");
        }
        1 => {
            let decrypted = rc5_32.decrypt_cbc_pad(&data, &key);

            fs::write(args.save_path, decrypted.0)
                .expect("Failed to save decryption result to file");
        }
        _ => unreachable!("Wrong operation code"),
    }
}
