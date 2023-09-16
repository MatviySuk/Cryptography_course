use std::{fmt, vec};
pub struct Digest(pub Vec<u8>);

pub struct RC5_32 {
    w: usize,
    r: usize,
    b: usize,
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
        $x.rotate_left(($s & ($w - 1))) | $x.rotate_right($w - ($s & ($w - 1)))
    };
}
macro_rules! rotr {
    ($x:expr, $s:expr, $w:expr) => {
        $x.rotate_right(($s & ($w - 1))) | $x.rotate_left($w - ($s & ($w - 1)))
    };
}

impl fmt::Debug for Digest {
    #[inline]
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(self, formatter)
    }
}

impl From<Vec<[u32; 2]>> for Digest {
    fn from(value: Vec<[u32; 2]>) -> Self {
        Digest(
            value
                .iter()
                .flat_map(|v| [v[0].to_le_bytes(), v[1].to_le_bytes()].concat())
                .collect::<Vec<u8>>(),
        )
    }
}

impl RC5_32 {
    pub fn new(r: u8, b: u8) -> Self {
        RC5_32 {
            w: 32,
            r: r as usize,
            b: b as usize,
        }
    }

    pub fn encrypt_cbc_pad(&self, iv: &[u8; 8], pt: &[u8], k: &[u8]) -> Digest {
        let s = self.expanded_key(k);
        let bb = 2 * self.w / 8;
        let n = 8 - ((iv.len() + pt.len()) % bb);
        let padding = vec![n as u8; n];

        [iv, pt, &padding]
            .concat()
            .chunks(8)
            .map(|c| {
                [
                    u32::from_le_bytes([c[4], c[5], c[6], c[7]]),
                    u32::from_le_bytes([c[0], c[1], c[2], c[3]]),
                ]
            })
            .scan([0u32; 2], |p, b| {
                let cb = self.encrypt_ecb(&[p[0] ^ b[0], p[1] ^ b[1]], &s);
                *p = cb;

                Some(cb)
            })
            .collect::<Vec<[u32; 2]>>()
            .into()
    }

    pub fn decrypt_cbc_pad(&self, ct: &[u8], k: &[u8]) -> Digest {
        let s = self.expanded_key(k);

        ct.chunks(8)
            .map(|c| {
                [
                    u32::from_le_bytes([c[0], c[1], c[2], c[3]]),
                    u32::from_le_bytes([c[4], c[5], c[6], c[7]]),
                ]
            })
            .scan([0u32; 2], |p, b| {
                let pt = self.decrypt_ecb(&b, &s);
                let res = Some([p[1] ^ pt[1], p[0] ^ pt[0]]);
                *p = b;

                res
            })
            .skip(1)
            .collect::<Vec<[u32; 2]>>()
            .into()
    }

    fn encrypt_ecb(&self, pt: &[u32; 2], s: &[u32]) -> [u32; 2] {
        let mut a = pt[0].wrapping_add(s[0]);
        let mut b = pt[1].wrapping_add(s[1]);

        for i in 1..self.r {
            a = rotl!((a ^ b), b, self.w as u32).wrapping_add(s[2 * i]);
            b = rotl!((b ^ a), a, self.w as u32).wrapping_add(s[2 * i + 1]);
        }

        [a, b]
    }

    fn decrypt_ecb(&self, ct: &[u32; 2], s: &[u32]) -> [u32; 2] {
        let mut b = ct[1];
        let mut a = ct[0];

        for i in (1..self.r).rev() {
            b = rotr!(b.wrapping_sub(s[2 * i + 1]), a, self.w as u32) ^ a;
            a = rotr!(a.wrapping_sub(s[2 * i]), b, self.w as u32) ^ b;
        }

        [a.wrapping_sub(s[0]), b.wrapping_sub(s[1])]
    }

    fn expanded_key(&self, k: &[u8]) -> Vec<u32> {
        let c = (8 * self.b) / self.w;
        let t = 2 * (self.r + 1);
        let u = self.w / 8;

        let p = 0xb7e15163u32;
        let q = 0x9e3779b9u32;

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
            a = rotl!((s[i].wrapping_add(a).wrapping_add(b)), 3, self.w as u32);
            s[i] = a;

            b = rotl!(
                (l[j].wrapping_add(a).wrapping_add(b)),
                a.wrapping_add(b),
                self.w as u32
            );
            l[j] = b;

            i = (i + 1) % t;
            j = (j + 1) % c;
        }

        s
    }
}
