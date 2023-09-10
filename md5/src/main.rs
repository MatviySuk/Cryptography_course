use clap::Parser;
use std::fs;
use std::io::Write;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// String data or file path to generate hash from
    #[arg(short, long)]
    data: String,

    /// File path with hash to validate hashed data
    #[arg(short, long)]
    hash_path: Option<String>,

    /// File path to save result hash
    #[arg(short, long, default_value = "hash")]
    save_path: String,
}

fn main() {
    let args = Args::parse();

    let data = match fs::read_to_string(args.data.as_str()) {
        Ok(file_text) => file_text,
        Err(_) => args.data,
    }
    .as_bytes()
    .to_vec();

    let hash = md5_algo::compute(data);
    println!("Result hash: {:02X}", hash);

    if let Some(hash_path) = args.hash_path {
        match fs::read_to_string(hash_path) {
            Ok(check_hash) => {
                let validation = check_hash.to_uppercase() == format!("{:02X}", hash);

                println!("Data is valid: {validation}");
            }
            Err(e) => {
                println!("Failed to validate hashes. Err: {}", e);
            }
        };
    } else {
        fs::write(args.save_path.clone(), format!("{:02X}", hash)).unwrap_or_else(|e| {
            println!(
                "Failed to save hash: {:02X} to the file: {}.\n Err: {e}",
                hash, args.save_path
            )
        });
    }
}
