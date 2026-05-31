//! Quantização para int16 (escala ×10000), idêntica ao pipeline C++ provado.

/// Quantiza um valor em espaço de feature: v*10000, clamp [-10000,10000],
/// arredondamento "ties away from zero" (igual a llround do C++).
#[inline]
pub fn quantize(v: f64) -> i16 {
    let mut s = v * 10000.0;
    if s < -10000.0 {
        s = -10000.0;
    }
    if s > 10000.0 {
        s = 10000.0;
    }
    // f64::round arredonda metade-pra-longe-do-zero, igual a std::llround.
    s.round() as i16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic() {
        assert_eq!(quantize(0.5), 5000);
        assert_eq!(quantize(-0.1), -1000);
        assert_eq!(quantize(1.5), 10000); // clamp
        assert_eq!(quantize(-1.0), -10000);
        assert_eq!(quantize(0.0), 0);
        assert_eq!(quantize(1.0), 10000);
    }
}
