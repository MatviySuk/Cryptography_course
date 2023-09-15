use std::time::SystemTime;
use random::LCGRandom;

fn main() {
    let key_phrase = "lkasjdlkj1lkejlasdkj80asdlggkmlksad";
    let pt = [0xEEu8, 0xDB, 0xA5, 0x21, 0x6D, 0x8F, 0xBB, 0x15];

    let key = &md5_algo::compute(key_phrase.as_bytes().to_vec()).0[8..];
    let seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Failed to generate seed")
        .as_secs();
    let iv = LCGRandom::new(1103515245, 12345, 2147483647, seed as u32).generate();
    println!("IV: {}", iv);

    let rc5 = rc5_algo::RC5_32::new(16, 8);
    let cypher = rc5.encrypt_ecb(&pt, key);
    let decrypted = rc5.decrypt_ecb(cypher.0.as_slice(), key);

    println!("Data:\t\t {:02X}", rc5_algo::Digest(pt.to_vec()));
    println!("Cypher:\t\t {:02X}\n", cypher);

    println!("Data:\t\t {:02X}", rc5_algo::Digest(pt.to_vec()));
    println!("Decrypted:\t {:02X}", decrypted);
}
