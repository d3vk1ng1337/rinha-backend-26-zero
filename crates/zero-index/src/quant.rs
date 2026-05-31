#[inline]
pub fn quantize(v: f64) -> i16 {
    let mut s = v * 10000.0;
    if s < -10000.0 {
        s = -10000.0;
    }
    if s > 10000.0 {
        s = 10000.0;
    }
    // ties away from zero, matching std::llround
    s.round() as i16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        assert_eq!(quantize(0.5), 5000);
        assert_eq!(quantize(-0.1), -1000);
        assert_eq!(quantize(1.5), 10000);
        assert_eq!(quantize(-1.0), -10000);
        assert_eq!(quantize(0.0), 0);
        assert_eq!(quantize(1.0), 10000);
    }
}
