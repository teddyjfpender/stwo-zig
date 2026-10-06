// Equivalent to square256.s31.json: 256 iterations of x <- x*x + 7 mod M31.
const P: u64 = 2147483647;
const ROUNDS: u32 = 256;

fn m31_step(x: u32) -> u32 {
    let wide: u64 = x.into();
    let product = wide * wide + 7_u64;
    let first = (product & P) + (product / 2147483648_u64);
    let second = (first & P) + (first / 2147483648_u64);
    let reduced = if second >= P {
        second - P
    } else {
        second
    };
    reduced.try_into().unwrap()
}

pub fn square256(x: u16) -> u32 {
    let mut value: u32 = x.into();
    let mut i = 0_u32;
    while i < ROUNDS {
        value = m31_step(value);
        i += 1;
    }
    value
}

#[executable]
fn main(x0: u16, x1: u16, x2: u16, x3: u16) -> (u32, u32, u32, u32, u32, u32, u32, u32) {
    (
        x0.into(),
        x1.into(),
        x2.into(),
        x3.into(),
        square256(x0),
        square256(x1),
        square256(x2),
        square256(x3),
    )
}

#[cfg(test)]
mod tests {
    use super::square256;

    #[test]
    fn same_example_values() {
        assert_eq!(square256(1), 1381993681);
        assert_eq!(square256(2), 1163620247);
        assert_eq!(square256(3), 833240539);
        assert_eq!(square256(65535), 2139095920);
    }
}
