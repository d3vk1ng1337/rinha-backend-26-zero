//! Gate de accuracy local: roda o test-data.json oficial contra o índice e
//! reporta FP/FN/weighted_E vs `expected_approved`/`expected_fraud_score`.
//! No Mac (arm64) é DIRECIONAL — o árbitro bit-exato é o gate amd64. Mas como
//! a busca é inteira e a normalização é f32 IEEE, deve casar.

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
        eprintln!("uso: {} <index.bin> <test-data.json> [nprobe={NPROBE}]", args[0]);
        std::process::exit(1);
    }
    let index_path = &args[1];
    let test_path = &args[2];
    let nprobe: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(NPROBE);

    #[cfg(target_arch = "x86_64")]
    eprintln!("PATH: {}", if std::is_x86_feature_detected!("avx2") { "AVX2" } else { "scalar" });
    #[cfg(not(target_arch = "x86_64"))]
    eprintln!("PATH: scalar (arm64)");

    let raw = fs::read(index_path).expect("read index");
    let idx = Index::from_bytes(&raw).expect("parse index (magic/version/layout)");
    eprintln!("índice: k={} n={} blocks={}", idx.k, idx.n, idx.total_blocks);

    let t0 = Instant::now();
    let data: serde_json::Value =
        serde_json::from_slice(&fs::read(test_path).expect("read test-data")).expect("parse json");
    let entries = data["entries"].as_array().expect("entries[]");
    eprintln!("{} queries carregadas em {:?}", entries.len(), t0.elapsed());

    let (mut total, mut parse_fail) = (0u64, 0u64);
    let (mut fp, mut fn_, mut exact, mut approve_match) = (0u64, 0u64, 0u64, 0u64);
    let mut score_hist = [0u64; 6];

    let t1 = Instant::now();
    for e in entries {
        total += 1;
        let req = &e["request"];
        let body = serde_json::to_vec(req).expect("serialize request");
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
            fp += 1; // previu fraude, era legítimo
        }
        if pred_approved && !exp_approved {
            fn_ += 1; // previu legítimo, era fraude
        }
    }
    let weighted_e = fp * 1 + fn_ * 3;

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
