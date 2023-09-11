use clap::Parser;
use random::LCGRandom;
use std::fs::OpenOptions;
use std::io::Write;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Multiplier value
    #[arg(short)]
    a: i32,    

    /// Seed or start value
    #[arg(short, long)]
    seed: i32,

    /// Modulus value
    #[arg(short, long)]
    modulus: i32, 

    /// Increment value
    #[arg(short)]
    c: i32,

    /// File name
    #[arg(short, long, default_value_t = 10)]
    iteration: i32,     

    /// File name
    #[arg(short, long, default_value = "random.txt")]
    file_name: String,      

    /// Find period of algorithm
    #[arg(short, long, default_value = "false")]
    period: String,  
}

fn main() {
    let args = Args::parse();
    let mut lcg_random = random::LCGRandom::new(args.a, args.c, args.modulus, args.seed);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(args.file_name)
        .expect("Failed to open file.");

    for _ in 0..args.iteration {
        let seed = lcg_random.generate();

        println!("{}", seed);
        file.write_all(format!("{}\n", seed).as_bytes()).expect("Failed to write into file.");
    }

    if args.period.eq_ignore_ascii_case("true") {
        let period = LCGRandom::period(args.a, args.c, args.modulus, args.seed);
        println!("Period: {}", period);
    }
}