use random::LCGRandom;
use std::time::SystemTime;
use std::{fmt, vec};
pub struct Digest(pub Vec<u8>);

    #[derive(Debug)]
pub struct RC5 {
    w: RC5WordSize,
    r: usize,
    b: usize,
}

#[derive(Clone, Debug)]
pub enum RC5WordSize {
    Bits16,
    Bits32,
    Bits64,
}

pub enum RC5ExpandedKey {
    Bits16(Vec<u16>),
    Bits32(Vec<u32>),
    Bits64(Vec<u64>),
}

macro_rules! implement {
    ($kind:ident, $format:expr) => {
        impl fmt::$kind for Digest {
            fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                for value in &self.0 {
                    write!(formatter, $format, value)?;
                }
                Ok(())
            }
        }
    };
}

implement!(LowerHex, "{:02x}");
implement!(UpperHex, "{:02X}");

macro_rules! rotl {
    ($x:expr, $s:expr, $w:expr) => {
        $x.rotate_left((($s as u32) & ($w - 1) as u32))
            | $x.rotate_right(($w as u32) - ($s as u32 & ($w - 1) as u32))
    };
}
macro_rules! rotr {
    ($x:expr, $s:expr, $w:expr) => {
        $x.rotate_right((($s as u32) & ($w - 1) as u32))
            | $x.rotate_left(($w as u32) - ($s as u32 & ($w - 1) as u32))
    };
}

impl fmt::Debug for Digest {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, formatter)
    }
}

impl From<Vec<u8>> for Digest {
    fn from(value: Vec<u8>) -> Self {
        Digest(value)
    }
}

impl From<&RC5WordSize> for usize {
    fn from(value: &RC5WordSize) -> Self {
        match value {
            RC5WordSize::Bits16 => 16usize,
            RC5WordSize::Bits32 => 32usize,
            RC5WordSize::Bits64 => 64usize,
        }
    }
}

impl RC5 {
    pub fn new(w: RC5WordSize, r: u8, b: u8) -> Self {
        RC5 {
            w,
            r: r as usize,
            b: b as usize,
        }
    }

    pub fn generate_key(&self, data: &[u8]) -> Vec<u8> {
        let key_hash = md5_algo::compute(data.to_vec());

        match self.b {
            8 => key_hash.0[8..].to_vec(),
            16 => key_hash.0.to_vec(),
            32 => [md5_algo::compute(key_hash.0.to_vec()).0, key_hash.0].concat(),
            _ => unreachable!("Incorrect octets number in key"),
        }
    }

    pub fn encrypt_cbc_pad(&self, pt: &[u8], k: &[u8]) -> Digest {
        let w: usize = (&self.w).into();
        let bb = 2 * w / 8;

        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Failed to generate seed")
            .as_nanos();
        let mut lcg_rand = LCGRandom::new(1103515245, 12345, 2147483647, seed as u32);

        let iv: Vec<u8> = (0..bb)
            .flat_map(|_| lcg_rand.generate().to_le_bytes())
            .collect();
        let n = bb - ((iv.len() + pt.len()) % bb);
        let padding = vec![n as u8; n];

        let s = match self.w {
            RC5WordSize::Bits16 => RC5ExpandedKey::Bits16(self.expanded_key_16(k)),
            RC5WordSize::Bits32 => RC5ExpandedKey::Bits32(self.expanded_key_32(k)),
            RC5WordSize::Bits64 => RC5ExpandedKey::Bits64(self.expanded_key_64(k)),
        };

        [iv.as_slice(), pt, padding.as_slice()]
            .concat()
            .chunks(bb)
            .scan(vec![0u8; bb], |p, b| {
                let pt = b
                    .iter()
                    .zip(p.iter())
                    .map(|(b, p)| b ^ p)
                    .collect::<Vec<u8>>();
                let cb = match &s {
                    RC5ExpandedKey::Bits16(s) => self.encrypt_ecb_16(&pt, s),
                    RC5ExpandedKey::Bits32(s) => self.encrypt_ecb_32(&pt, s),
                    RC5ExpandedKey::Bits64(s) => self.encrypt_ecb_64(&pt, s),
                };
                *p = cb.clone();

                Some(cb)
            })
            .flatten()
            .collect::<Vec<u8>>()
            .into()
    }

    pub fn decrypt_cbc_pad(&self, ct: &[u8], k: &[u8]) -> Digest {
        let w: usize = (&self.w).into();
        let bb = 2 * w / 8;
        let s = match self.w {
            RC5WordSize::Bits16 => RC5ExpandedKey::Bits16(self.expanded_key_16(k)),
            RC5WordSize::Bits32 => RC5ExpandedKey::Bits32(self.expanded_key_32(k)),
            RC5WordSize::Bits64 => RC5ExpandedKey::Bits64(self.expanded_key_64(k)),
        };

        ct.chunks(bb)
            .scan(vec![0u8; bb], |p, b| {
                let pt = match &s {
                    RC5ExpandedKey::Bits16(s) => self.decrypt_ecb_16(b, s),
                    RC5ExpandedKey::Bits32(s) => self.decrypt_ecb_32(b, s),
                    RC5ExpandedKey::Bits64(s) => self.decrypt_ecb_64(b, s),
                };

                let res = p
                    .iter()
                    .zip(pt.iter())
                    .map(|(p, pt)| p ^ pt)
                    .collect::<Vec<u8>>();

                *p = b.to_vec();

                Some(res)
            })
            .flatten()
            .skip(w)
            .collect::<Vec<u8>>()
            .into()
    }

    fn encrypt_ecb_16(&self, pt: &[u8], s: &[u16]) -> Vec<u8> {
        let w: usize = (&self.w).into();
        let pt = [
            u16::from_le_bytes([pt[2], pt[3]]),
            u16::from_le_bytes([pt[0], pt[1]]),
        ];

        let mut a = pt[0].wrapping_add(s[0]);
        let mut b = pt[1].wrapping_add(s[1]);

        for i in 1..self.r {
            a = rotl!((a ^ b), b, w).wrapping_add(s[2 * i]);
            b = rotl!((b ^ a), a, w).wrapping_add(s[2 * i + 1]);
        }

        [a.to_le_bytes(), b.to_le_bytes()].concat()
    }

    fn encrypt_ecb_32(&self, pt: &[u8], s: &[u32]) -> Vec<u8> {
        let w: usize = (&self.w).into();
        let pt = [
            u32::from_le_bytes([pt[4], pt[5], pt[6], pt[7]]),
            u32::from_le_bytes([pt[0], pt[1], pt[2], pt[3]]),
        ];

        let mut a = pt[0].wrapping_add(s[0]);
        let mut b = pt[1].wrapping_add(s[1]);

        for i in 1..self.r {
            a = rotl!((a ^ b), b, w).wrapping_add(s[2 * i]);
            b = rotl!((b ^ a), a, w).wrapping_add(s[2 * i + 1]);
        }

        [a.to_le_bytes(), b.to_le_bytes()].concat()
    }

    fn encrypt_ecb_64(&self, pt: &[u8], s: &[u64]) -> Vec<u8> {
        let w: usize = (&self.w).into();
        let pt = [
            u64::from_le_bytes([pt[8], pt[9], pt[10], pt[11], pt[12], pt[13], pt[14], pt[15]]),
            u64::from_le_bytes([pt[0], pt[1], pt[2], pt[3], pt[4], pt[5], pt[6], pt[7]]),
        ];

        let mut a = pt[0].wrapping_add(s[0]);
        let mut b = pt[1].wrapping_add(s[1]);

        for i in 1..self.r {
            a = rotl!((a ^ b), b, w).wrapping_add(s[2 * i]);
            b = rotl!((b ^ a), a, w).wrapping_add(s[2 * i + 1]);
        }

        [a.to_le_bytes(), b.to_le_bytes()].concat()
    }

    fn decrypt_ecb_16(&self, ct: &[u8], s: &[u16]) -> Vec<u8> {
        let w: usize = (&self.w).into();
        let ct = [
            u16::from_le_bytes([ct[0], ct[1]]),
            u16::from_le_bytes([ct[2], ct[3]]),
        ];

        let mut b = ct[1];
        let mut a = ct[0];

        for i in (1..self.r).rev() {
            b = rotr!(b.wrapping_sub(s[2 * i + 1]), a, w) ^ a;
            a = rotr!(a.wrapping_sub(s[2 * i]), b, w) ^ b;
        }

        [
            b.wrapping_sub(s[1]).to_le_bytes(),
            a.wrapping_sub(s[0]).to_le_bytes(),
        ]
        .concat()
    }

    fn decrypt_ecb_32(&self, ct: &[u8], s: &[u32]) -> Vec<u8> {
        let w: usize = (&self.w).into();
        let ct = [
            u32::from_le_bytes([ct[0], ct[1], ct[2], ct[3]]),
            u32::from_le_bytes([ct[4], ct[5], ct[6], ct[7]]),
        ];

        let mut b = ct[1];
        let mut a = ct[0];

        for i in (1..self.r).rev() {
            b = rotr!(b.wrapping_sub(s[2 * i + 1]), a, w) ^ a;
            a = rotr!(a.wrapping_sub(s[2 * i]), b, w) ^ b;
        }

        [
            b.wrapping_sub(s[1]).to_le_bytes(),
            a.wrapping_sub(s[0]).to_le_bytes(),
        ]
        .concat()
    }

    fn decrypt_ecb_64(&self, ct: &[u8], s: &[u64]) -> Vec<u8> {
        let w: usize = (&self.w).into();
        let ct = [
            u64::from_le_bytes([ct[0], ct[1], ct[2], ct[3], ct[4], ct[5], ct[6], ct[7]]),
            u64::from_le_bytes([ct[8], ct[9], ct[10], ct[11], ct[12], ct[13], ct[14], ct[15]]),
        ];

        let mut b = ct[1];
        let mut a = ct[0];

        for i in (1..self.r).rev() {
            b = rotr!(b.wrapping_sub(s[2 * i + 1]), a, w) ^ a;
            a = rotr!(a.wrapping_sub(s[2 * i]), b, w) ^ b;
        }

        [
            b.wrapping_sub(s[1]).to_le_bytes(),
            a.wrapping_sub(s[0]).to_le_bytes(),
        ]
        .concat()
    }

    fn expanded_key_16(&self, k: &[u8]) -> Vec<u16> {
        let w: usize = (&self.w).into();
        let c = (8 * self.b) / w;
        let t = 2 * (self.r + 1);
        let u = w / 8;

        let p = 0xb7e1_u16;
        let q = 0x9e37_u16;

        let mut s = vec![0u16; t];
        let mut l = vec![0u16; c];

        for i in (0..(self.b - 1)).rev() {
            l[i / u] = l[i / u].rotate_left(8u32).wrapping_add(k[i] as u16)
        }

        s[0] = p;
        for i in 1..t {
            s[i] = s[i - 1].wrapping_add(q);
        }

        let mut i = 0usize;
        let mut j = 0usize;
        let mut a = 0u16;
        let mut b = 0u16;

        for _ in 0..(3 * t) {
            a = rotl!((s[i].wrapping_add(a).wrapping_add(b)), 3, w);
            s[i] = a;

            b = rotl!((l[j].wrapping_add(a).wrapping_add(b)), a.wrapping_add(b), w);
            l[j] = b;

            i = (i + 1) % t;
            j = (j + 1) % c;
        }

        s
    }

    fn expanded_key_32(&self, k: &[u8]) -> Vec<u32> {
        let w: usize = (&self.w).into();
        let c = (8 * self.b) / w;
        let t = 2 * (self.r + 1);
        let u = w / 8;

        let p = 0xb7e1_5163_u32;
        let q = 0x9e37_79b9_u32;

        let mut s = vec![0u32; t];
        let mut l = vec![0u32; c];

        for i in (0..(self.b - 1)).rev() {
            l[i / u] = l[i / u].rotate_left(8u32).wrapping_add(k[i] as u32)
        }

        s[0] = p;
        for i in 1..t {
            s[i] = s[i - 1].wrapping_add(q);
        }

        let mut i = 0usize;
        let mut j = 0usize;
        let mut a = 0u32;
        let mut b = 0u32;

        for _ in 0..(3 * t) {
            a = rotl!((s[i].wrapping_add(a).wrapping_add(b)), 3, w);
            s[i] = a;

            b = rotl!((l[j].wrapping_add(a).wrapping_add(b)), a.wrapping_add(b), w);
            l[j] = b;

            i = (i + 1) % t;
            j = (j + 1) % c;
        }

        s
    }

    fn expanded_key_64(&self, k: &[u8]) -> Vec<u64> {
        let w: usize = (&self.w).into();
        let c = (8 * self.b) / w;
        let t = 2 * (self.r + 1);
        let u = w / 8;

        let p = 0xb7e1_5162_8aed_2a6b_u64;
        let q = 0x9e37_79b9_7f4a_7c15_u64;

        let mut s = vec![0u64; t];
        let mut l = vec![0u64; c];

        for i in (0..(self.b - 1)).rev() {
            l[i / u] = l[i / u].rotate_left(8u32).wrapping_add(k[i] as u64)
        }

        s[0] = p;
        for i in 1..t {
            s[i] = s[i - 1].wrapping_add(q);
        }

        let mut i = 0usize;
        let mut j = 0usize;
        let mut a = 0u64;
        let mut b = 0u64;

        for _ in 0..(3 * t) {
            a = rotl!((s[i].wrapping_add(a).wrapping_add(b)), 3, w);
            s[i] = a;

            b = rotl!((l[j].wrapping_add(a).wrapping_add(b)), a.wrapping_add(b), w);
            l[j] = b;

            i = (i + 1) % t;
            j = (j + 1) % c;
        }

        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rc5_16_ecb() {
        let r = 16;
        let b = 8;
        let data = b"abcd";
        let key_phrase = b"HelloWorldKey";

        let rc5 = RC5::new(RC5WordSize::Bits16, r, b);
        let key = rc5.generate_key(key_phrase);
        let s = rc5.expanded_key_16(&key);

        let cypher = rc5.encrypt_ecb_16(data, &s);
        let decrypted = rc5.decrypt_ecb_16(&cypher, &s);

        assert_eq!(
            format!("{:02x}", Digest(data.to_vec())),
            format!("{:02x}", Digest(decrypted))
        );
    }

    #[test]
    fn test_rc5_32_ecb() {
        let r = 16;
        let b = 8;
        let data = b"abcdefgh";
        let key_phrase = b"HelloWorldKey";

        let rc5 = RC5::new(RC5WordSize::Bits32, r, b);
        let key = rc5.generate_key(key_phrase);
        let s = rc5.expanded_key_32(&key);

        let cypher = rc5.encrypt_ecb_32(data, &s);
        let decrypted = rc5.decrypt_ecb_32(&cypher, &s);

        assert_eq!(
            format!("{:02x}", Digest(data.to_vec())),
            format!("{:02x}", Digest(decrypted))
        );
    }

    #[test]
    fn test_rc5_64_ecb() {
        let r = 16;
        let b = 8;
        let data = b"abcdefghijklmnop";
        let key_phrase = b"HelloWorldKey";

        let rc5 = RC5::new(RC5WordSize::Bits64, r, b);
        let key = rc5.generate_key(key_phrase);
        let s = rc5.expanded_key_64(&key);

        let cypher = rc5.encrypt_ecb_64(data, &s);
        let decrypted = rc5.decrypt_ecb_64(&cypher, &s);

        assert_eq!(
            format!("{:02x}", Digest(data.to_vec())),
            format!("{:02x}", Digest(decrypted))
        );
    }

    #[test]
    fn test_rc5_cbc_pad() {
        let r = 16;
        let b = 8;
        let data = b"l";
        let key_phrase = b"HelloWorldKey";

        vec![
            RC5WordSize::Bits16,
            RC5WordSize::Bits32,
            RC5WordSize::Bits64,
        ]
        .iter()
        .map(|w| {
            let bb = 2 * (usize::from(w) / 8);
            let rc5 = RC5::new(w.clone(), r, b);
            let key = rc5.generate_key(key_phrase);

            let cypher = rc5.encrypt_cbc_pad(data, &key);
            let decrypted = rc5.decrypt_cbc_pad(cypher.0.as_slice(), &key);

            let n_last = decrypted.0.last().map_or(0, |&l| {
                if decrypted.0[(decrypted.0.len() - (l as usize))..]
                    .iter()
                    .all(|&e| e == l)
                    && l <= (bb as u8)
                {
                    return l;
                }
                0
            }) as usize;

            decrypted.0[..(decrypted.0.len() - n_last)].to_vec()
        })
        .all(|d| {
            assert_eq!(
                format!("{:02x}", Digest(data.to_vec())),
                format!("{:02x}", Digest(d))
            );

            true
        });
    }
}
