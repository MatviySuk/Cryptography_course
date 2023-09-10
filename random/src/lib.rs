
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
}