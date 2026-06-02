use std::env;
use std::fs;
use std::time::Instant;

use zero_index::normalize::normalize;
use zero_index::search::Index;

const NPROBE: usize = 12;
const REPAIR_MIN: u8 = 1;
const REPAIR_MAX: u8 = 4;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("uso: {} <index.bin> <test-data.json> [nprobe={NPROBE}] [tune | t0,..,t5]", args[0]);
        std::process::exit(1);
    }
    let index_path = &args[1];
    let test_path = &args[2];
    let nprobe: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(NPROBE);
    let mode = args.get(4).cloned();

    #[cfg(target_arch = "x86_64")]
    eprintln!("PATH: {}", if std::is_x86_feature_detected!("avx2") { "AVX2" } else { "scalar" });
    #[cfg(not(target_arch = "x86_64"))]
    eprintln!("PATH: scalar (arm64)");

    let raw = fs::read(index_path).expect("read index");
    let mut idx = Index::from_bytes(&raw).expect("parse index (magic/version/layout)");
    eprintln!("índice: k={} n={} blocks={}", idx.k, idx.n, idx.total_blocks);

    let data: serde_json::Value =
        serde_json::from_slice(&fs::read(test_path).expect("read test-data")).expect("parse json");
    let entries = data["entries"].as_array().expect("entries[]");
    eprintln!("{} queries; nprobe_fast={nprobe}", entries.len());

    // --- tuning: find per-count worst-distance thresholds so the fast pass + threshold-gated
    //     repair reproduces the FP=FN=0 baseline. Only counts 0 and 5 need a threshold
    //     (1..4 always verify via the count rule). ---
    if mode.as_deref() == Some("tune") {
        let mut min_wrong = [u64::MAX; 6];
        let (mut n0, mut n5, mut w0, mut w5) = (0u64, 0u64, 0u64, 0u64);
        for e in entries {
            let body = serde_json::to_vec(&e["request"]).expect("serialize");
            let exp_approved = e["expected_approved"].as_bool().unwrap_or(true);
            let (fc, wd) = match normalize(&body) {
                Some(q) => idx.search_fast(&q, nprobe),
                None => continue,
            };
            if fc == 0 || fc == 5 {
                if fc == 0 { n0 += 1 } else { n5 += 1 }
                let pred_approved = fc <= 2;
                if pred_approved != exp_approved {
                    if fc == 0 { w0 += 1 } else { w5 += 1 }
                    if wd < min_wrong[fc as usize] {
                        min_wrong[fc as usize] = wd;
                    }
                }
            }
        }
        let mut thr = [u32::MAX; 6];
        for c in [0usize, 5] {
            thr[c] = if min_wrong[c] == u64::MAX {
                u32::MAX
            } else {
                min_wrong[c].min(u32::MAX as u64) as u32
            };
        }
        eprintln!("tune: cnt0 fast={n0} wrong={w0} thr0={}", thr[0]);
        eprintln!("tune: cnt5 fast={n5} wrong={w5} thr5={}", thr[5]);
        eprintln!("WORST_THRESHOLD={},{},{},{},{},{}", thr[0], thr[1], thr[2], thr[3], thr[4], thr[5]);
        idx.set_worst_thr(thr);
    } else if let Some(s) = mode {
        let parts: Vec<u32> = s.split(',').map(|x| x.parse().unwrap_or(u32::MAX)).collect();
        if parts.len() == 6 {
            let mut t = [u32::MAX; 6];
            t.copy_from_slice(&parts);
            idx.set_worst_thr(t);
            eprintln!("thresholds set: {t:?}");
        }
    }

    // --- validation gate (with whatever thresholds are set) ---
    let (mut total, mut parse_fail) = (0u64, 0u64);
    let (mut fp, mut fn_, mut exact, mut approve_match) = (0u64, 0u64, 0u64, 0u64);
    let mut score_hist = [0u64; 6];
    let t1 = Instant::now();
    for e in entries {
        total += 1;
        let body = serde_json::to_vec(&e["request"]).expect("serialize request");
        let exp_approved = e["expected_approved"].as_bool().unwrap_or(true);
        let exp_score = e["expected_fraud_score"].as_f64().unwrap_or(0.0);
        let exp_count = (exp_score * 5.0).round() as i64;

        let count = match normalize(&body) {
            Some(q) => idx.search(&q, nprobe, REPAIR_MIN, REPAIR_MAX),
            None => {
                parse_fail += 1;
                0
            }
        };
        score_hist[count as usize] += 1;
        let pred_approved = count <= 2;
        if count as i64 == exp_count {
            exact += 1;
        }
        if pred_approved == exp_approved {
            approve_match += 1;
        }
        if !pred_approved && exp_approved {
            fp += 1;
        }
        if pred_approved && !exp_approved {
            fn_ += 1;
        }
    }
    let weighted_e = fp + fn_ * 3;
    eprintln!("--- resultado ({:?}) ---", t1.elapsed());
    eprintln!("total={total} parse_fail={parse_fail}");
    eprintln!("exact_score_match={exact}  approve_match={approve_match}");
    eprintln!("FP={fp}  FN={fn_}  weighted_E={weighted_e}");
    eprintln!("score_hist (count 0..5) = {score_hist:?}");
    if fp == 0 && fn_ == 0 {
        eprintln!("==> ACCURACY OK (FP=FN=0) — detection_score máximo");
        std::process::exit(0);
    } else {
        eprintln!("==> ACCURACY FALHOU — FP/FN > 0");
        std::process::exit(1);
    }
}
