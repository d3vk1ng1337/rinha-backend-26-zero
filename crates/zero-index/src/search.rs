use crate::format::{block_pair_offset, layout_for, IndexLayout, BLOCK, DIMS, MAGIC, PAIRS, VERSION};

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

#[inline]
fn rd_i16(raw: &[u8], off: usize) -> i16 {
    i16::from_le_bytes([raw[off], raw[off + 1]])
}
#[inline]
fn rd_u32(raw: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]])
}

struct Top5 {
    dist: [u64; 5],
    label: [u8; 5],
    worst: usize,
}
impl Top5 {
    #[inline]
    fn new() -> Self {
        Top5 { dist: [u64::MAX; 5], label: [0; 5], worst: 0 }
    }
    #[inline]
    fn worst_dist(&self) -> u64 {
        self.dist[self.worst]
    }
    #[inline]
    fn add(&mut self, d: u64, l: u8) {
        if d >= self.dist[self.worst] {
            return;
        }
        self.dist[self.worst] = d;
        self.label[self.worst] = l;
        let mut w = 0;
        for i in 1..5 {
            if self.dist[i] > self.dist[w] {
                w = i;
            }
        }
        self.worst = w;
    }
    #[inline]
    fn fraud(&self) -> u8 {
        self.label[0] + self.label[1] + self.label[2] + self.label[3] + self.label[4]
    }
}

pub struct Index<'a> {
    raw: &'a [u8],
    pub k: usize,
    pub n: u32,
    pub total_blocks: usize,
    l: IndexLayout,
    n_groups: usize,
    // pair-SoA tables for the AVX2 path
    cpsoa: Vec<i16>,
    bpsoa_min: Vec<i16>,
    bpsoa_max: Vec<i16>,
}

impl<'a> Index<'a> {
    pub fn from_bytes(raw: &'a [u8]) -> Option<Index<'a>> {
        if raw.len() < 64 {
            return None;
        }
        let magic = u64::from_le_bytes(raw[0..8].try_into().ok()?);
        let version = rd_u32(raw, 8);
        let n = rd_u32(raw, 12);
        let k = rd_u32(raw, 16);
        let total_blocks = rd_u32(raw, 20);
        let block_size = rd_u32(raw, 24);
        let dims = rd_u32(raw, 28);
        if magic != MAGIC || version != VERSION || dims as usize != DIMS || block_size as usize != BLOCK {
            return None;
        }
        let l = layout_for(k, total_blocks);
        if l.total > raw.len() {
            return None;
        }
        let k = k as usize;
        let n_groups = (k + 7) / 8;

        let mut idx = Index {
            raw,
            k,
            n,
            total_blocks: total_blocks as usize,
            l,
            n_groups,
            cpsoa: vec![0; n_groups * PAIRS * 16],
            bpsoa_min: vec![0; n_groups * PAIRS * 16],
            bpsoa_max: vec![0; n_groups * PAIRS * 16],
        };
        idx.build_soa();
        Some(idx)
    }

    fn build_soa(&mut self) {
        for g in 0..self.n_groups {
            for p in 0..PAIRS {
                let base = (g * PAIRS + p) * 16;
                for lane in 0..8 {
                    let c = g * 8 + lane;
                    if c < self.k {
                        for k2 in 0..2 {
                            let d = p * 2 + k2;
                            self.cpsoa[base + lane * 2 + k2] = self.centroid(c, d);
                            self.bpsoa_min[base + lane * 2 + k2] = self.bmin(c, d);
                            self.bpsoa_max[base + lane * 2 + k2] = self.bmax(c, d);
                        }
                    }
                }
            }
        }
    }

    #[inline]
    fn centroid(&self, c: usize, d: usize) -> i16 {
        rd_i16(self.raw, self.l.centroids + (c * DIMS + d) * 2)
    }
    #[inline]
    fn bmin(&self, c: usize, d: usize) -> i16 {
        rd_i16(self.raw, self.l.bbox_min + (c * DIMS + d) * 2)
    }
    #[inline]
    fn bmax(&self, c: usize, d: usize) -> i16 {
        rd_i16(self.raw, self.l.bbox_max + (c * DIMS + d) * 2)
    }
    #[inline]
    fn block_start(&self, c: usize) -> u32 {
        rd_u32(self.raw, self.l.offsets + c * 4)
    }
    #[inline]
    fn count(&self, c: usize) -> u32 {
        rd_u32(self.raw, self.l.counts + c * 4)
    }
    #[inline]
    fn block_val(&self, block_id: usize, idx: usize) -> i16 {
        rd_i16(self.raw, self.l.blocks + (block_id * DIMS * BLOCK + idx) * 2)
    }
    #[inline]
    fn label(&self, block_id: usize, lane: usize) -> u8 {
        self.raw[self.l.labels + block_id * BLOCK + lane]
    }

    #[inline]
    pub fn search(&self, q: &[i16; DIMS], nprobe: usize, repair_min: u8, repair_max: u8) -> u8 {
        #[cfg(target_arch = "x86_64")]
        {
            if std::is_x86_feature_detected!("avx2") {
                return unsafe { self.search_avx2(q, nprobe, repair_min, repair_max) };
            }
        }
        self.search_scalar(q, nprobe, repair_min, repair_max)
    }

    #[inline]
    fn dist_centroid(&self, q: &[i16; DIMS], c: usize) -> u64 {
        let mut s: i64 = 0;
        for d in 0..DIMS {
            let diff = q[d] as i64 - self.centroid(c, d) as i64;
            s += diff * diff;
        }
        s as u64
    }
    #[inline]
    fn bbox_lb(&self, q: &[i16; DIMS], c: usize) -> u64 {
        let mut s: i64 = 0;
        for d in 0..DIMS {
            let qd = q[d] as i64;
            let mn = self.bmin(c, d) as i64;
            let mx = self.bmax(c, d) as i64;
            let gap = if qd < mn { mn - qd } else if qd > mx { qd - mx } else { 0 };
            s += gap * gap;
        }
        s as u64
    }
    fn scan_cluster(&self, c: usize, q: &[i16; DIMS], top: &mut Top5) {
        let cnt = self.count(c) as usize;
        if cnt == 0 {
            return;
        }
        let start = self.block_start(c) as usize;
        let nblocks = (cnt + BLOCK - 1) / BLOCK;
        for bi in 0..nblocks {
            let block_id = start + bi;
            let valid = core::cmp::min(BLOCK, cnt - bi * BLOCK);
            for lane in 0..valid {
                let limit = top.worst_dist();
                let mut s: u64 = 0;
                for d in 0..DIMS {
                    let diff = q[d] as i64 - self.block_val(block_id, block_pair_offset(d, lane)) as i64;
                    s += (diff * diff) as u64;
                    if s >= limit {
                        break;
                    }
                }
                top.add(s, self.label(block_id, lane));
            }
        }
    }

    fn search_scalar(&self, q: &[i16; DIMS], nprobe: usize, repair_min: u8, repair_max: u8) -> u8 {
        let kk = self.k;
        let np = nprobe.clamp(1, 64).min(kk);
        let mut best_c = [0usize; 64];
        let mut best_d = [u64::MAX; 64];
        let mut used = 0usize;
        let mut worst = 0u64;
        let mut worst_i = 0usize;
        for c in 0..kk {
            let d = self.dist_centroid(q, c);
            if used < np {
                best_c[used] = c;
                best_d[used] = d;
                if used == 0 || d > worst {
                    worst = d;
                    worst_i = used;
                }
                used += 1;
            } else if d < worst {
                best_c[worst_i] = c;
                best_d[worst_i] = d;
                worst = best_d[0];
                worst_i = 0;
                for i in 1..used {
                    if best_d[i] > worst {
                        worst = best_d[i];
                        worst_i = i;
                    }
                }
            }
        }
        for i in 1..used {
            let (c, d) = (best_c[i], best_d[i]);
            let mut j = i;
            while j > 0 && best_d[j - 1] > d {
                best_d[j] = best_d[j - 1];
                best_c[j] = best_c[j - 1];
                j -= 1;
            }
            best_d[j] = d;
            best_c[j] = c;
        }
        let mut top = Top5::new();
        let words = (kk + 63) / 64;
        let mut scanned = vec![0u64; words];
        for i in 0..used {
            let c = best_c[i];
            if i > 0 && self.bbox_lb(q, c) >= top.worst_dist() {
                scanned[c >> 6] |= 1u64 << (c & 63);
                continue;
            }
            self.scan_cluster(c, q, &mut top);
            scanned[c >> 6] |= 1u64 << (c & 63);
        }
        let mut fraud = top.fraud();
        if fraud >= repair_min && fraud <= repair_max {
            let mut cands: Vec<(u64, usize)> = Vec::new();
            for c in 0..kk {
                if scanned[c >> 6] & (1u64 << (c & 63)) != 0 || self.count(c) == 0 {
                    continue;
                }
                let lb = self.bbox_lb(q, c);
                if lb < top.worst_dist() {
                    cands.push((lb, c));
                }
            }
            cands.sort_unstable_by_key(|&(lb, _)| lb);
            for (lb, c) in cands {
                if lb >= top.worst_dist() {
                    break;
                }
                self.scan_cluster(c, q, &mut top);
                let now = top.fraud();
                if now < repair_min || now > repair_max {
                    break;
                }
            }
            fraud = top.fraud();
        }
        fraud
    }
}

#[cfg(target_arch = "x86_64")]
impl<'a> Index<'a> {
    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn make_qpair(q: &[i16; DIMS], p: usize) -> __m256i {
        let lo = (q[p * 2] as u16) as u32;
        let hi = (q[p * 2 + 1] as u16) as u32;
        _mm256_set1_epi32((lo | (hi << 16)) as i32)
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn spair(blk: *const i16, p: usize, vq: &[__m256i; PAIRS]) -> __m256i {
        let vc = _mm256_loadu_si256(blk.add(p * 16) as *const __m256i);
        let df = _mm256_sub_epi16(vq[p], vc);
        _mm256_madd_epi16(df, df)
    }

    #[inline]
    #[target_feature(enable = "avx2")]
    unsafe fn update_top5(dist: u32, label: u8, td: &mut [u32; 5], tl: &mut [u8; 5], max_top: &mut u32) {
        if dist >= *max_top {
            return;
        }
        let mut i: isize = 3;
        while i >= 0 && dist < td[i as usize] {
            td[(i + 1) as usize] = td[i as usize];
            tl[(i + 1) as usize] = tl[i as usize];
            i -= 1;
        }
        td[(i + 1) as usize] = dist;
        tl[(i + 1) as usize] = label;
        *max_top = td[4];
    }

    #[target_feature(enable = "avx2")]
    unsafe fn find_top_centroids(&self, vq: &[__m256i; PAIRS], out: &mut [u32], n: usize) {
        let mut top_d = [u32::MAX; 64];
        let mut top_c = [0u32; 64];
        for i in 0..n {
            top_c[i] = i as u32;
        }
        let mut worst = u32::MAX;
        let cpsoa = self.cpsoa.as_ptr();
        for g in 0..self.n_groups {
            let src = cpsoa.add(g * PAIRS * 16);
            let mut acc = _mm256_setzero_si256();
            for p in 0..PAIRS {
                let vc = _mm256_loadu_si256(src.add(p * 16) as *const __m256i);
                let diff = _mm256_sub_epi16(vq[p], vc);
                acc = _mm256_add_epi32(acc, _mm256_madd_epi16(diff, diff));
            }
            let mut vals = [0u32; 8];
            _mm256_storeu_si256(vals.as_mut_ptr() as *mut __m256i, acc);
            let base = (g * 8) as u32;
            let lim = core::cmp::min(8usize, self.k - g * 8);
            for i in 0..lim {
                let v = vals[i];
                if v >= worst {
                    continue;
                }
                let mut wi = 0;
                for j in 1..n {
                    if top_d[j] > top_d[wi] {
                        wi = j;
                    }
                }
                top_d[wi] = v;
                top_c[wi] = base + i as u32;
                worst = 0;
                for j in 0..n {
                    if top_d[j] > worst {
                        worst = top_d[j];
                    }
                }
            }
        }
        for i in 0..n - 1 {
            for j in i + 1..n {
                if top_d[j] < top_d[i] {
                    top_d.swap(i, j);
                    top_c.swap(i, j);
                }
            }
        }
        for i in 0..n {
            out[i] = top_c[i];
        }
    }

    #[target_feature(enable = "avx2")]
    unsafe fn scan_cluster_avx2(&self, vq: &[__m256i; PAIRS], c: usize, td: &mut [u32; 5], tl: &mut [u8; 5], max_top: &mut u32) {
        let cnt = self.count(c) as usize;
        if cnt == 0 {
            return;
        }
        let blk_start = self.block_start(c) as usize;
        let nblocks = (cnt + BLOCK - 1) / BLOCK;
        let blocks_base = self.raw.as_ptr().add(self.l.blocks) as *const i16;
        for bi_off in 0..nblocks {
            let bi = blk_start + bi_off;
            let blk = blocks_base.add(bi * DIMS * BLOCK);
            let vmax = _mm256_set1_epi32(core::cmp::min(*max_top, i32::MAX as u32) as i32);
            let mut acc0 = Self::spair(blk, 0, vq);
            let mut acc1 = Self::spair(blk, 1, vq);
            acc0 = _mm256_add_epi32(acc0, Self::spair(blk, 2, vq));
            // pruning checkpoint: bail once partial sum already exceeds the top-5 worst
            if _mm256_movemask_epi8(_mm256_cmpgt_epi32(vmax, _mm256_add_epi32(acc0, acc1))) == 0 {
                continue;
            }
            acc1 = _mm256_add_epi32(acc1, Self::spair(blk, 3, vq));
            acc0 = _mm256_add_epi32(acc0, Self::spair(blk, 4, vq));
            if _mm256_movemask_epi8(_mm256_cmpgt_epi32(vmax, _mm256_add_epi32(acc0, acc1))) == 0 {
                continue;
            }
            acc1 = _mm256_add_epi32(acc1, Self::spair(blk, 5, vq));
            acc0 = _mm256_add_epi32(acc0, Self::spair(blk, 6, vq));
            let mut dists = [0u32; 8];
            _mm256_storeu_si256(dists.as_mut_ptr() as *mut __m256i, _mm256_add_epi32(acc0, acc1));
            let pos = bi_off * BLOCK;
            let n_valid = core::cmp::min(BLOCK, cnt - pos);
            let lbl = self.raw.as_ptr().add(self.l.labels + bi * BLOCK);
            for j in 0..n_valid {
                Self::update_top5(dists[j], *lbl.add(j), td, tl, max_top);
            }
        }
    }

    #[target_feature(enable = "avx2")]
    unsafe fn bbox_lb8(&self, g: usize, vq: &[__m256i; PAIRS], lbs: &mut [u32; 8]) {
        let smin = self.bpsoa_min.as_ptr().add(g * PAIRS * 16);
        let smax = self.bpsoa_max.as_ptr().add(g * PAIRS * 16);
        let zero = _mm256_setzero_si256();
        let mut acc = _mm256_setzero_si256();
        for p in 0..PAIRS {
            let vmn = _mm256_loadu_si256(smin.add(p * 16) as *const __m256i);
            let vmx = _mm256_loadu_si256(smax.add(p * 16) as *const __m256i);
            let gap_lo = _mm256_max_epi16(zero, _mm256_sub_epi16(vmn, vq[p]));
            let gap_hi = _mm256_max_epi16(zero, _mm256_sub_epi16(vq[p], vmx));
            let gap = _mm256_max_epi16(gap_lo, gap_hi);
            acc = _mm256_add_epi32(acc, _mm256_madd_epi16(gap, gap));
        }
        _mm256_storeu_si256(lbs.as_mut_ptr() as *mut __m256i, acc);
    }

    #[target_feature(enable = "avx2")]
    unsafe fn repair(&self, vq: &[__m256i; PAIRS], skip: &[u32], nskip: usize, td: &mut [u32; 5], tl: &mut [u8; 5], max_top: &mut u32, repair_min: u8, repair_max: u8) {
        let words = (self.k + 63) / 64;
        let mut skip_set = vec![0u64; words];
        for &s in &skip[..nskip] {
            skip_set[(s >> 6) as usize] |= 1u64 << (s & 63);
        }
        let mut cands: Vec<(u32, u32)> = Vec::with_capacity(256);
        let mut lbs = [0u32; 8];
        for g in 0..self.n_groups {
            self.bbox_lb8(g, vq, &mut lbs);
            let base = (g * 8) as u32;
            for i in 0..8 {
                let c = base + i as u32;
                if (c as usize) >= self.k {
                    continue;
                }
                if lbs[i] >= *max_top {
                    continue;
                }
                if skip_set[(c >> 6) as usize] & (1u64 << (c & 63)) != 0 {
                    continue;
                }
                if self.count(c as usize) == 0 {
                    continue;
                }
                cands.push((lbs[i], c));
            }
        }
        cands.sort_unstable_by_key(|&(lb, _)| lb);
        for (lb, c) in cands {
            if lb >= *max_top {
                break;
            }
            self.scan_cluster_avx2(vq, c as usize, td, tl, max_top);
            let now = tl[0] + tl[1] + tl[2] + tl[3] + tl[4];
            if now < repair_min || now > repair_max {
                break;
            }
        }
    }

    #[target_feature(enable = "avx2")]
    unsafe fn search_avx2(&self, q: &[i16; DIMS], nprobe: usize, repair_min: u8, repair_max: u8) -> u8 {
        let np = nprobe.clamp(1, 64).min(self.k);
        let mut vq = [_mm256_setzero_si256(); PAIRS];
        for p in 0..PAIRS {
            vq[p] = Self::make_qpair(q, p);
        }
        let mut probes = [0u32; 64];
        self.find_top_centroids(&vq, &mut probes, np);

        let mut td = [u32::MAX; 5];
        let mut tl = [0u8; 5];
        let mut max_top = u32::MAX;
        for i in 0..np {
            self.scan_cluster_avx2(&vq, probes[i] as usize, &mut td, &mut tl, &mut max_top);
        }
        let mut cnt = tl[0] + tl[1] + tl[2] + tl[3] + tl[4];
        if cnt >= repair_min && cnt <= repair_max {
            self.repair(&vq, &probes, np, &mut td, &mut tl, &mut max_top, repair_min, repair_max);
            cnt = tl[0] + tl[1] + tl[2] + tl[3] + tl[4];
        }
        cnt
    }
}
