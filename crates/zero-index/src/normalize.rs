//! Normalização 14-dim do corpo JSON de /fraud-score → vetor int16.
//! Porte BIT-A-BIT do `normalizer.hpp` do top1 (dalvorsn), que crava accuracy
//! 6000: features computadas em f32 (via `fast_f32`), depois ×10000 em f64 +
//! arredondamento (`quantize`). NÃO trocar f32→f64 nas features: o boundary de
//! arredondamento é o que faz casar com o ground-truth oficial.

use crate::quant::quantize;

const INV_MAX_AMOUNT: f32 = 1.0 / 10000.0;
const INV_MAX_INSTALLMENTS: f32 = 1.0 / 12.0;
const INV_AMOUNT_VS_AVG: f32 = 1.0 / 10.0;
const INV_MAX_MINUTES: f32 = 1.0 / 1440.0;
const INV_MAX_KM: f32 = 1.0 / 1000.0;
const INV_MAX_TX_COUNT: f32 = 1.0 / 20.0;
const INV_MAX_MERCHANT_AVG: f32 = 1.0 / 10000.0;
const INV_23: f32 = 1.0 / 23.0;
const INV_6: f32 = 1.0 / 6.0;

#[inline]
fn clampf(v: f32) -> f32 {
    if v < 0.0 {
        0.0
    } else if v > 1.0 {
        1.0
    } else {
        v
    }
}

#[inline]
fn mcc_risk(mcc: &[u8]) -> f32 {
    match mcc {
        b"5411" => 0.15,
        b"5812" => 0.30,
        b"5912" => 0.20,
        b"5944" => 0.45,
        b"7801" => 0.80,
        b"7802" => 0.75,
        b"7995" => 0.85,
        b"4511" => 0.35,
        b"5311" => 0.25,
        b"5999" => 0.50,
        _ => 0.5,
    }
}

/// Parser de float idêntico ao `fast_f32` do dalvorsn: parte inteira em u32,
/// parte fracionária em u32/divisor, ambos castados pra f32 e somados em f32.
#[inline]
fn fast_f32(b: &[u8], mut p: usize) -> f32 {
    let n = b.len();
    let mut w: u32 = 0;
    while p < n && b[p].wrapping_sub(b'0') <= 9 {
        w = w * 10 + (b[p] - b'0') as u32;
        p += 1;
    }
    if p >= n || b[p] != b'.' {
        return w as f32;
    }
    p += 1;
    let mut f: u32 = 0;
    let mut d: u32 = 1;
    while p < n && b[p].wrapping_sub(b'0') <= 9 && d < 100_000_000 {
        f = f * 10 + (b[p] - b'0') as u32;
        d *= 10;
        p += 1;
    }
    w as f32 + f as f32 / d as f32
}

#[inline]
fn digit2(b: &[u8], p: usize) -> i32 {
    ((b[p] - b'0') as i32) * 10 + (b[p + 1] - b'0') as i32
}

#[inline]
fn digit4(b: &[u8], p: usize) -> i32 {
    ((b[p] - b'0') as i32) * 1000
        + ((b[p + 1] - b'0') as i32) * 100
        + ((b[p + 2] - b'0') as i32) * 10
        + (b[p + 3] - b'0') as i32
}

/// Sakamoto (segunda=0).
#[inline]
fn fast_weekday(y: i32, m: i32, d: i32) -> i32 {
    const T: [i32; 12] = [0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4];
    let mut y = y;
    if m < 3 {
        y -= 1;
    }
    let dow = (y + y / 4 - y / 100 + y / 400 + T[(m - 1) as usize] + d) % 7;
    (dow + 6) % 7
}

/// Howard Hinnant civil→epoch (segundos).
#[inline]
fn fast_epoch(y: i32, m: i32, d: i32, hh: i32, mm: i32, ss: i32) -> i64 {
    let (mut y, mut m) = (y, m);
    if m <= 2 {
        y -= 1;
        m += 9;
    } else {
        m -= 3;
    }
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = (y - era * 400) as i64;
    let m = m as i64;
    let doy = (153 * m + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era as i64 * 146097 + doe - 719468;
    days * 86400 + hh as i64 * 3600 + mm as i64 * 60 + ss as i64
}

#[derive(PartialEq, Clone, Copy)]
enum Sec {
    Root,
    Tx,
    Cust,
    Merch,
    Term,
    Last,
}

/// Normaliza o corpo JSON cru em um vetor int16[14]. `None` se malformado.
pub fn normalize(js: &[u8]) -> Option<[i16; 14]> {
    let end = js.len();
    let mut sec = Sec::Root;
    let mut depth: i32 = 0;

    let (mut tx_amount, mut tx_inst, mut cust_avg, mut cnt24) = (0f32, 0f32, 0f32, 0f32);
    let (mut merch_avg, mut km_home, mut km_cur) = (0f32, 0f32, 0f32);
    let (mut is_online, mut card_present, mut has_last) = (false, false, false);
    let mut rat: Option<usize> = None;
    let mut last_ts: Option<usize> = None;
    let mut mid: Option<(usize, usize)> = None;
    let mut mcc: Option<(usize, usize)> = None;
    let mut kms: Vec<(usize, usize)> = Vec::with_capacity(32);

    let mut p = 0usize;
    while p < end {
        let c = js[p];
        p += 1;
        if c == b'{' {
            depth += 1;
            continue;
        }
        if c == b'}' {
            depth -= 1;
            if depth == 1 {
                sec = Sec::Root;
            }
            continue;
        }
        if c != b'"' {
            continue;
        }
        let key_start = p;
        while p < end && js[p] != b'"' {
            p += 1;
        }
        let key = &js[key_start..p];
        if p < end {
            p += 1; // aspas de fechamento
        }
        while p < end && (js[p] == b' ' || js[p] == b'\t') {
            p += 1;
        }
        if p >= end || js[p] != b':' {
            continue;
        }
        p += 1;
        while p < end && (js[p] == b' ' || js[p] == b'\t') {
            p += 1;
        }
        if p >= end {
            return None;
        }
        let vstart = p;
        let vc = js[p];
        match sec {
            Sec::Root => {
                if key == b"transaction" {
                    sec = Sec::Tx;
                } else if key == b"customer" {
                    sec = Sec::Cust;
                } else if key == b"merchant" {
                    sec = Sec::Merch;
                } else if key == b"terminal" {
                    sec = Sec::Term;
                } else if key == b"last_transaction" && vc != b'n' {
                    has_last = true;
                    sec = Sec::Last;
                }
            }
            Sec::Tx => {
                if key == b"amount" {
                    tx_amount = fast_f32(js, vstart);
                } else if key == b"installments" {
                    tx_inst = fast_f32(js, vstart);
                } else if key == b"requested_at" {
                    rat = Some(vstart + 1);
                }
            }
            Sec::Cust => {
                if key == b"avg_amount" {
                    cust_avg = fast_f32(js, vstart);
                } else if key == b"tx_count_24h" {
                    cnt24 = fast_f32(js, vstart);
                } else if key == b"known_merchants" && vc == b'[' {
                    p += 1;
                    while p < end && js[p] != b']' {
                        while p < end && js[p] != b'"' && js[p] != b']' {
                            p += 1;
                        }
                        if p >= end || js[p] == b']' {
                            break;
                        }
                        p += 1;
                        let s = p;
                        while p < end && js[p] != b'"' {
                            p += 1;
                        }
                        kms.push((s, p - s));
                        if p < end {
                            p += 1;
                        }
                    }
                    if p < end {
                        p += 1;
                    }
                }
            }
            Sec::Merch => {
                if key == b"id" {
                    let s = vstart + 1;
                    let mut q = s;
                    while q < end && js[q] != b'"' {
                        q += 1;
                    }
                    mid = Some((s, q - s));
                } else if key == b"mcc" {
                    let s = vstart + 1;
                    let mut q = s;
                    while q < end && js[q] != b'"' {
                        q += 1;
                    }
                    mcc = Some((s, q - s));
                } else if key == b"avg_amount" {
                    merch_avg = fast_f32(js, vstart);
                }
            }
            Sec::Term => {
                if key == b"is_online" {
                    is_online = vc == b't';
                } else if key == b"card_present" {
                    card_present = vc == b't';
                } else if key == b"km_from_home" {
                    km_home = fast_f32(js, vstart);
                }
            }
            Sec::Last => {
                if key == b"timestamp" {
                    last_ts = Some(vstart + 1);
                } else if key == b"km_from_current" {
                    km_cur = fast_f32(js, vstart);
                }
            }
        }
    }

    let rat = rat?;
    let mid = mid?;

    let y = digit4(js, rat);
    let mo = digit2(js, rat + 5);
    let dy = digit2(js, rat + 8);
    let hh = digit2(js, rat + 11);
    let mi = digit2(js, rat + 14);
    let ss = digit2(js, rat + 17);

    let mut vec = [0f32; 14];
    vec[0] = clampf(tx_amount * INV_MAX_AMOUNT);
    vec[1] = clampf(tx_inst * INV_MAX_INSTALLMENTS);
    let cav = if cust_avg > 0.0 { cust_avg } else { 1.0 };
    vec[2] = clampf((tx_amount / cav) * INV_AMOUNT_VS_AVG);
    vec[3] = (hh as f32) * INV_23;
    vec[4] = (fast_weekday(y, mo, dy) as f32) * INV_6;

    if !has_last || last_ts.is_none() {
        vec[5] = -1.0;
        vec[6] = -1.0;
    } else {
        let lt = last_ts.unwrap();
        let ly = digit4(js, lt);
        let lmo = digit2(js, lt + 5);
        let ld = digit2(js, lt + 8);
        let lhh = digit2(js, lt + 11);
        let lmi = digit2(js, lt + 14);
        let lss = digit2(js, lt + 17);
        let req_e = fast_epoch(y, mo, dy, hh, mi, ss);
        let last_e = fast_epoch(ly, lmo, ld, lhh, lmi, lss);
        vec[5] = clampf(((req_e - last_e) as f32) / 60.0 * INV_MAX_MINUTES);
        vec[6] = clampf(km_cur * INV_MAX_KM);
    }

    vec[7] = clampf(km_home * INV_MAX_KM);
    vec[8] = clampf(cnt24 * INV_MAX_TX_COUNT);
    vec[9] = if is_online { 1.0 } else { 0.0 };
    vec[10] = if card_present { 1.0 } else { 0.0 };

    let (ms, ml) = mid;
    let known = kms
        .iter()
        .any(|&(s, l)| l == ml && js[s..s + l] == js[ms..ms + ml]);
    vec[11] = if known { 0.0 } else { 1.0 };

    vec[12] = match mcc {
        Some((s, l)) => mcc_risk(&js[s..s + l]),
        None => 0.5,
    };
    vec[13] = clampf(merch_avg * INV_MAX_MERCHANT_AVG);

    let mut out = [0i16; 14];
    for i in 0..14 {
        out[i] = quantize(vec[i] as f64);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // test-data.json entry 0 (expected_fraud_score = 0)
    const ENTRY0: &[u8] = br#"{"id":"tx-1641912674","transaction":{"amount":441.59,"installments":1,"requested_at":"2027-07-09T16:31:06Z"},"customer":{"avg_amount":883.18,"tx_count_24h":1,"known_merchants":["MERC-004","MERC-017"]},"merchant":{"id":"MERC-004","mcc":"5411","avg_amount":302.78},"terminal":{"is_online":false,"card_present":true,"km_from_home":33.8814492067},"last_transaction":{"timestamp":"2027-06-04T14:14:22Z","km_from_current":18.4353521556}}"#;

    // last_transaction null → sentinela nas dims 5,6
    const ENTRY_NULL_LAST: &[u8] = br#"{"id":"tx-1","transaction":{"amount":41.12,"installments":2,"requested_at":"2026-03-11T18:45:53Z"},"customer":{"avg_amount":82.24,"tx_count_24h":3,"known_merchants":["MERC-003","MERC-016"]},"merchant":{"id":"MERC-099","mcc":"7995","avg_amount":60.25},"terminal":{"is_online":true,"card_present":false,"km_from_home":29.2331036248},"last_transaction":null}"#;

    #[test]
    fn normalize_entry0() {
        let v = normalize(ENTRY0).expect("parse");
        assert_eq!(v[0], 442, "amount 441.59/10000");
        assert_eq!(v[1], 833, "installments 1/12");
        assert_eq!(v[2], 500, "441.59/883.18/10 = 0.05");
        assert_eq!(v[9], 0, "is_online false");
        assert_eq!(v[10], 10000, "card_present true");
        assert_eq!(v[11], 0, "MERC-004 in known_merchants");
        assert_eq!(v[12], 1500, "mcc 5411 = 0.15");
        // dims 5,6 computadas (tem last_transaction)
        assert!(v[5] >= 0, "minutes since last computed");
    }

    #[test]
    fn normalize_null_last() {
        let v = normalize(ENTRY_NULL_LAST).expect("parse");
        assert_eq!(v[5], -10000, "sentinela -1 ×10000");
        assert_eq!(v[6], -10000, "sentinela -1 ×10000");
        assert_eq!(v[9], 10000, "is_online true");
        assert_eq!(v[10], 0, "card_present false");
        assert_eq!(v[11], 10000, "MERC-099 not in known");
        assert_eq!(v[12], 8500, "mcc 7995 = 0.85");
    }
}
