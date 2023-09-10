

fn main() {
    let data = b"12345678901234567890123456789012345678901234567890123456789012345678901234567890";

    let hash = md5::compute(data.to_vec());
    println!("Hash: {:x}", hash);
}