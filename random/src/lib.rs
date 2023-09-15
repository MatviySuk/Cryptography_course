// linear congruential generator
pub struct LCGRandom {
    a: u128,
    c: u128,
    m: u128,
    s: u128,
}

impl LCGRandom {
    pub fn new(a: u32, c: u32, m: u32, s: u32) -> Self {
        LCGRandom {
            a: a as u128,
            c: c as u128,
            m: m as u128,
            s: s as u128,
        }
    }

    pub fn generate(&mut self) -> u32 {
        let seed = (self.a * self.s + self.c) % self.m;
        self.s = seed;

        seed as u32
    }

    pub fn generate_n(&mut self, n: u32) -> u32 {
        for _ in 0..n {
            self.generate();
        }

        self.s as u32
    }

    pub fn period(a: u32, c: u32, m: u32, s: u32) -> u32 {
        let mut slow: LCGRandom = LCGRandom::new(a, c, m, s);
        let mut fast: LCGRandom = LCGRandom::new(a, c, m, s);
        let mut i = 0;

        while slow.generate() != fast.generate_n(2) {}

        loop {
            fast.generate();
            i += 1;

            if slow.s == fast.s {
                return i;
            }
        }
    }
}
