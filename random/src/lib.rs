// linear congruential generator
pub struct LCGRandom {
    a: i32,
    c: i32,
    m: i32,
    s: i32,
}

impl LCGRandom {
    pub fn new(a: i32, c: i32, m: i32, s: i32) -> Self {
        LCGRandom { a, c, m, s }
    }

    pub fn generate(&mut self) -> i32 {
        let seed = (self.a * self.s + self.c) % self.m;
        self.s = seed;

        seed
    }

    pub fn generate_n(&mut self, n: i32) -> i32 {
        for _ in 0..n {
            self.generate();
        }

        self.s
    }

    pub fn period(a: i32, c: i32, m: i32, s: i32) -> i32 {
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
