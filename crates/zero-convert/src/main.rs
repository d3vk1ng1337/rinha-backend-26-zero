//! Converter: references.json[.gz] -> índice IVF pair-SoA (index.bin).
//! k-means++ (k=4096, sample=50000, iters=50) -> assign -> blocos pair-SoA +
//! bbox por cluster. Roda em build-time (Docker amd64) e localmente p/ o gate.

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::time::Instant;

use flate2::read::GzDecoder;
use rayon::prelude::*;
use zero_index::format::{block_pair_offset, layout_for, BLOCK, DIMS};
use zero_index::quant::quantize;

const DEFAULT_K: u32 = 4096;
const DEFAULT_SAMPLE: u32 = 50_000;
const DEFAULT_ITERS: u32 = 50;

/// SplitMix64 — RNG determinístico simples (não precisa casar com o C++).
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
    fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

fn read_input(path: &str) -> Vec<u8> {
    let mut f = File::open(path).expect("open input");
    let mut buf = Vec::new();
    if path.ends_with(".gz") {
        let mut gz = GzDecoder::new(f);
        gz.read_to_end(&mut buf).expect("gunzip");
    } else {
        f.read_to_end(&mut buf).expect("read");
    }
    buf
}

fn parse_references(buf: &[u8]) -> (Vec<i16>, Vec<u8>) {
    let n = buf.len();
    let mut vecs: Vec<i16> = Vec::with_capacity(3_200_000 * DIMS);
    let mut labels: Vec<u8> = Vec::with_capacity(3_200_000);
    let mut p = 0usize;
    loop {
        while p < n && buf[p] != b'{' && buf[p] != b']' {
            p += 1;
        }
        if p >= n || buf[p] == b']' {
            break;
        }
        let obj_start = p;
        let mut depth = 0i32;
        let mut q = p;
        while q < n {
            match buf[q] {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            q += 1;
        }
        let obj_end = q.min(n - 1);
        let obj = &buf[obj_start..=obj_end];

        // vector: primeiro '[' do objeto
        let mut ok = false;
        if let Some(ab) = obj.iter().position(|&c| c == b'[') {
            let mut np = ab + 1;
            let mut cnt = 0usize;
            while cnt < DIMS && np < obj.len() {
                while np < obj.len()
                    && matches!(obj[np], b' ' | b'\t' | b'\r' | b'\n' | b',')
                {
                    np += 1;
                }
                if np >= obj.len() || obj[np] == b']' {
                    break;
                }
                let s = np;
                while np < obj.len()
                    && !matches!(obj[np], b',' | b']' | b' ' | b'\t' | b'\r' | b'\n')
                {
                    np += 1;
                }
                let v: f64 = std::str::from_utf8(&obj[s..np])
                    .ok()
                    .and_then(|t| t.parse().ok())
                    .unwrap_or(0.0);
                vecs.push(quantize(v));
                cnt += 1;
            }
            if cnt == DIMS {
                ok = true;
            } else {
                vecs.truncate(vecs.len() - cnt);
            }
        }
        if ok {
            let is_fraud = obj.windows(5).any(|w| w == b"fraud");
            labels.push(if is_fraud { 1 } else { 0 });
        }
        p = obj_end + 1;
    }
    (vecs, labels)
}

#[inline]
fn dist_to_centroid(p: &[i16], c: &[f32; DIMS]) -> f32 {
    let mut s = 0f32;
    for d in 0..DIMS {
        let diff = p[d] as f32 - c[d];
        s += diff * diff;
    }
    s
}

fn nearest_centroid(p: &[i16], centroids: &[[f32; DIMS]]) -> u32 {
    let mut best = 0u32;
    let mut best_d = dist_to_centroid(p, &centroids[0]);
    for (c, cent) in centroids.iter().enumerate().skip(1) {
        let d = dist_to_centroid(p, cent);
        if d < best_d {
            best_d = d;
            best = c as u32;
        }
    }
    best
}

fn vec_at(vecs: &[i16], i: usize) -> &[i16] {
    &vecs[i * DIMS..i * DIMS + DIMS]
}

fn init_kmeans_pp(vecs: &[i16], sample: &[u32], k: u32, seed: u64) -> Vec<[f32; DIMS]> {
    let k = k as usize;
    let mut centroids = vec![[0f32; DIMS]; k];
    let mut dmin = vec![f32::INFINITY; sample.len()];
    let mut rng = Rng(seed);

    let first = vec_at(vecs, sample[rng.below(sample.len())] as usize);
    for d in 0..DIMS {
        centroids[0][d] = first[d] as f32;
    }
    for c in 1..k {
        let prev = centroids[c - 1];
        let mut sum = 0f64;
        for (i, &si) in sample.iter().enumerate() {
            let dist = dist_to_centroid(vec_at(vecs, si as usize), &prev);
            if dist < dmin[i] {
                dmin[i] = dist;
            }
            sum += dmin[i] as f64;
        }
        if sum <= 0.0 {
            let pp = vec_at(vecs, sample[rng.below(sample.len())] as usize);
            for d in 0..DIMS {
                centroids[c][d] = pp[d] as f32;
            }
            continue;
        }
        let target = rng.unit() * sum;
        let mut acc = 0f64;
        let mut chosen = sample.len() - 1;
        for (i, _) in sample.iter().enumerate() {
            acc += dmin[i] as f64;
            if acc >= target {
                chosen = i;
                break;
            }
        }
        let pp = vec_at(vecs, sample[chosen] as usize);
        for d in 0..DIMS {
            centroids[c][d] = pp[d] as f32;
        }
    }
    centroids
}

fn train_kmeans(vecs: &[i16], sample: &[u32], centroids: &mut [[f32; DIMS]], iters: u32) {
    let k = centroids.len();
    let mut assign = vec![0u32; sample.len()];
    let mut rng = Rng(0xC0FFEE);
    for it in 0..iters {
        let new_assign: Vec<u32> = sample
            .par_iter()
            .map(|&si| nearest_centroid(vec_at(vecs, si as usize), centroids))
            .collect();
        let mut changed = 0u64;
        for i in 0..sample.len() {
            if new_assign[i] != assign[i] {
                changed += 1;
                assign[i] = new_assign[i];
            }
        }
        let mut sums = vec![0f64; k * DIMS];
        let mut counts = vec![0u32; k];
        for i in 0..sample.len() {
            let c = assign[i] as usize;
            counts[c] += 1;
            let p = vec_at(vecs, sample[i] as usize);
            let row = &mut sums[c * DIMS..c * DIMS + DIMS];
            for d in 0..DIMS {
                row[d] += p[d] as f64;
            }
        }
        for c in 0..k {
            if counts[c] == 0 {
                let p = vec_at(vecs, sample[rng.below(sample.len())] as usize);
                for d in 0..DIMS {
                    centroids[c][d] = p[d] as f32;
                }
            } else {
                let inv = 1.0 / counts[c] as f64;
                for d in 0..DIMS {
                    centroids[c][d] = (sums[c * DIMS + d] * inv) as f32;
                }
            }
        }
        eprintln!("  iter {}/{} changed={}", it + 1, iters, changed);
        if changed == 0 {
            break;
        }
    }
}

fn build_ivf(vecs: &[i16], labels: &[u8], k: u32, sample_sz: u32, iters: u32) -> Vec<u8> {
    let n = labels.len() as u32;
    let kk = k as usize;
    let mut rng = Rng(42);
    let actual_sample = sample_sz.min(n) as usize;
    let mut sample = vec![0u32; actual_sample];
    for s in sample.iter_mut() {
        *s = rng.below(n as usize) as u32;
    }

    eprintln!("k-means++ init (k={k}, n={n}, sample={actual_sample})...");
    let mut centroids = init_kmeans_pp(vecs, &sample, k, 42);
    eprintln!("training...");
    train_kmeans(vecs, &sample, &mut centroids, iters);

    eprintln!("assigning {n} vectors...");
    let assignment: Vec<u32> = (0..n as usize)
        .into_par_iter()
        .map(|i| nearest_centroid(vec_at(vecs, i), &centroids))
        .collect();

    let mut counts = vec![0u32; kk];
    for &c in &assignment {
        counts[c as usize] += 1;
    }

    let mut block_offsets = vec![0u32; kk + 1];
    for c in 0..kk {
        block_offsets[c + 1] = block_offsets[c] + (counts[c] + BLOCK as u32 - 1) / BLOCK as u32;
    }
    let total_blocks = block_offsets[kk];

    let mut starts = vec![0u32; kk + 1];
    for c in 0..kk {
        starts[c + 1] = starts[c] + counts[c];
    }
    let mut cursor = starts.clone();
    let mut order = vec![0u32; n as usize];
    for i in 0..n as usize {
        let c = assignment[i] as usize;
        order[cursor[c] as usize] = i as u32;
        cursor[c] += 1;
    }
    // ordena cada cluster por distância ao centroide (blocos iniciais = mais próximos)
    for c in 0..kk {
        if counts[c] < 2 {
            continue;
        }
        let s = starts[c] as usize;
        let e = s + counts[c] as usize;
        let cent = centroids[c];
        order[s..e].sort_unstable_by(|&a, &b| {
            let da = dist_to_centroid(vec_at(vecs, a as usize), &cent);
            let db = dist_to_centroid(vec_at(vecs, b as usize), &cent);
            da.partial_cmp(&db).unwrap()
        });
    }

    // serializa
    let layout = layout_for(k, total_blocks);
    let mut out = vec![0u8; layout.total];

    // header
    out[0..8].copy_from_slice(&zero_index::format::MAGIC.to_le_bytes());
    out[8..12].copy_from_slice(&zero_index::format::VERSION.to_le_bytes());
    out[12..16].copy_from_slice(&n.to_le_bytes());
    out[16..20].copy_from_slice(&k.to_le_bytes());
    out[20..24].copy_from_slice(&total_blocks.to_le_bytes());
    out[24..28].copy_from_slice(&(BLOCK as u32).to_le_bytes());
    out[28..32].copy_from_slice(&(DIMS as u32).to_le_bytes());

    let put_i16 = |out: &mut [u8], off: usize, v: i16| {
        out[off..off + 2].copy_from_slice(&v.to_le_bytes());
    };
    let put_u32 = |out: &mut [u8], off: usize, v: u32| {
        out[off..off + 4].copy_from_slice(&v.to_le_bytes());
    };

    // centroids (quantizados)
    for c in 0..kk {
        for d in 0..DIMS {
            let v = centroids[c][d].round() as i32;
            let v = v.clamp(-10000, 10000) as i16;
            put_i16(&mut out, layout.centroids + (c * DIMS + d) * 2, v);
        }
    }

    // bbox + blocos + labels
    let mut bmin = vec![i16::MAX; kk * DIMS];
    let mut bmax = vec![i16::MIN; kk * DIMS];
    for c in 0..kk {
        if counts[c] == 0 {
            for d in 0..DIMS {
                bmin[c * DIMS + d] = 0;
                bmax[c * DIMS + d] = 0;
            }
            continue;
        }
        let base = block_offsets[c];
        for pos in 0..counts[c] {
            let orig = order[(starts[c] + pos) as usize] as usize;
            let block = (base + pos / BLOCK as u32) as usize;
            let lane = (pos % BLOCK as u32) as usize;
            out[layout.labels + block * BLOCK + lane] = labels[orig];
            let src = vec_at(vecs, orig);
            for d in 0..DIMS {
                let v = src[d];
                let off = layout.blocks + (block * DIMS * BLOCK + block_pair_offset(d, lane)) * 2;
                put_i16(&mut out, off, v);
                if v < bmin[c * DIMS + d] {
                    bmin[c * DIMS + d] = v;
                }
                if v > bmax[c * DIMS + d] {
                    bmax[c * DIMS + d] = v;
                }
            }
        }
    }
    for c in 0..kk {
        for d in 0..DIMS {
            put_i16(&mut out, layout.bbox_min + (c * DIMS + d) * 2, bmin[c * DIMS + d]);
            put_i16(&mut out, layout.bbox_max + (c * DIMS + d) * 2, bmax[c * DIMS + d]);
        }
    }
    for c in 0..=kk {
        put_u32(&mut out, layout.offsets + c * 4, block_offsets[c]);
    }
    for c in 0..kk {
        put_u32(&mut out, layout.counts + c * 4, counts[c]);
    }
    out
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "uso: {} <references.json[.gz]> <out.bin> [k={DEFAULT_K}] [sample={DEFAULT_SAMPLE}] [iters={DEFAULT_ITERS}]",
            args[0]
        );
        std::process::exit(1);
    }
    let input = &args[1];
    let output = &args[2];
    let k: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_K);
    let sample: u32 = args.get(4).and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_SAMPLE);
    let iters: u32 = args.get(5).and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_ITERS);

    let t0 = Instant::now();
    eprintln!("lendo {input}...");
    let buf = read_input(input);
    eprintln!("  {} MB descomprimido em {:?}", buf.len() / (1024 * 1024), t0.elapsed());

    let t1 = Instant::now();
    let (vecs, labels) = parse_references(&buf);
    let n = labels.len();
    eprintln!("  {n} registros parseados em {:?}", t1.elapsed());
    drop(buf);

    let t2 = Instant::now();
    let out = build_ivf(&vecs, &labels, k, sample, iters);
    eprintln!("  índice construído em {:?}", t2.elapsed());

    let mut f = File::create(output).expect("create out");
    f.write_all(&out).expect("write out");
    eprintln!("escrito {output} ({} MB) em {:?} total", out.len() / (1024 * 1024), t0.elapsed());
}
