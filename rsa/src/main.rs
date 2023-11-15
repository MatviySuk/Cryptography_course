extern crate openssl;

use std::fs;
use openssl::rsa::Rsa;
use openssl::rsa::Padding;
use clap::{Args, Subcommand, Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    operation: Operation,
}

#[derive(Subcommand, Debug,)]
enum Operation {
    Keys(KeysArgs),
    Encrypt(CryptoArgs),
    Decrypt(CryptoArgs),
}

#[derive(Args, Debug,)]
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

#[derive(ValueEnum, Clone, Debug,)]
enum KeyType {
    Private,
    Public,
}

#[derive(Args, Debug,)]
struct CryptoArgs {
    /// File path to read data or cypher
    #[arg(short, long)]
    data_path: String,

    /// File path to save operation result
    #[arg(short, long, default_value = "")]
    result_path: String,

    /// File path to save generated keys
    #[arg(short, long, default_value = "")]
    keys_path: String,

    /// Key Type
    #[arg(value_enum)]
    key_type: KeyType,
}

fn main() { 
    let cli = Cli::parse();

    match cli.operation {
        Operation::Keys(args) => {
            // Generate an RSA key pair with 2048 bits
            if !(args.block_size != 0 && (args.block_size & (args.block_size - 1)) == 0) {
                panic!("Block size should be 2 in power of n. Current value is: {}", args.block_size);
            }

            let rsa = Rsa::generate(args.block_size)
                .expect("Failed to generate rsa keys!");

            // Extract the private key and public key
            let private_key = rsa.private_key_to_pem()
                .expect("Failed to generate private pem key!");
            let public_key = rsa.public_key_to_pem_pkcs1()
                .expect("Failed to generate public pem key!");

            // You can save the keys to files or use them in your application
            fs::write(format!("{}_key.pem", args.keys_name), private_key)
                .expect("Failed to save private pem key to file!");
            fs::write(format!("{}_key.pem.pub", args.keys_name), public_key)
                .expect("Failed to save public pem key to file!");
        },
        Operation::Encrypt(args) => {
            let data = fs::read(args.data_path)
                .expect("Unable to read data from the file!");
            let pem_key_data = fs::read(args.keys_path)
                .expect("Unable to read key from the file!");
            let mut cypher: Vec<u8>;
            
            let cypher_len =  match args.key_type {
                KeyType::Private => {
                    let private_key = Rsa::private_key_from_pem(&pem_key_data)
                        .expect("Failed to generate private key from pem file!");
                    cypher = vec![0; private_key.size() as usize];
                    private_key.private_encrypt(&data, &mut cypher, Padding::PKCS1).unwrap()
                },
                KeyType::Public => {
                    let public_key = Rsa::public_key_from_pem_pkcs1(&pem_key_data)
                        .expect("Failed to generate public key from pem file!");
                    cypher = vec![0; public_key.size() as usize];
                    public_key.public_encrypt(&data, &mut cypher, Padding::PKCS1).unwrap()
                },
            }; 

            cypher.truncate(cypher_len);
            
            fs::write(args.result_path, cypher)
                .expect("Failed to save decrypted data to file");
        },
        Operation::Decrypt(args) => {
            let cypher = fs::read(args.data_path)
                .expect("Unable to read cypher from the file!");
            let pem_key_data = fs::read(args.keys_path)
                .expect("Unable to read key from the file!");
            let mut decrypted: Vec<u8>;
            
            let decrypted_len =  match args.key_type {
                KeyType::Private => {
                    let private_key = Rsa::private_key_from_pem(&pem_key_data)
                        .expect("Failed to generate private key from pem file!");
                    decrypted = vec![0; private_key.size() as usize];
                    private_key.private_decrypt(&cypher, &mut decrypted, Padding::PKCS1).unwrap()
                },
                KeyType::Public => {
                    let public_key = Rsa::public_key_from_pem_pkcs1(&pem_key_data)
                        .expect("Failed to generate public key from pem file!");
                    decrypted = vec![0; public_key.size() as usize];
                    public_key.public_decrypt(&cypher, &mut decrypted, Padding::PKCS1).unwrap()
                },
            }; 

            decrypted.truncate(decrypted_len);
            
            fs::write(args.result_path, decrypted)
                .expect("Failed to save decrypted data to file");
        },
    };
}
