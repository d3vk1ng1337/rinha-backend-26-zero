//! Formato em disco do índice IVF (pair-SoA), idêntico ao layout C++ provado.

pub const DIMS: usize = 14;
pub const BLOCK: usize = 8;
pub const PAIRS: usize = DIMS / 2; // 7
pub const MAGIC: u64 = u64::from_le_bytes(*b"RH26ZERO");
pub const VERSION: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IndexHeader {
    pub magic: u64,
    pub version: u32,
    pub n: u32,
    pub k: u32,
    pub total_blocks: u32,
    pub block_size: u32,
    pub dims: u32,
    pub reserved: [u32; 8],
}

const _: () = assert!(core::mem::size_of::<IndexHeader>() == 64);

#[derive(Clone, Copy, Debug, Default)]
pub struct IndexLayout {
    pub centroids: usize,
    pub bbox_min: usize,
    pub bbox_max: usize,
    pub offsets: usize,
    pub counts: usize,
    pub labels: usize,
    pub blocks: usize,
    pub total: usize,
}

#[inline]
fn align_up(v: usize, a: usize) -> usize {
    (v + a - 1) & !(a - 1)
}

/// Offsets (em bytes) de cada seção, dado k clusters e total_blocks blocos.
pub fn layout_for(k: u32, total_blocks: u32) -> IndexLayout {
    let k = k as usize;
    let tb = total_blocks as usize;
    let mut off = core::mem::size_of::<IndexHeader>();
    let mut l = IndexLayout::default();
    l.centroids = off;
    off += k * DIMS * 2;
    l.bbox_min = off;
    off += k * DIMS * 2;
    l.bbox_max = off;
    off += k * DIMS * 2;
    off = align_up(off, 4);
    l.offsets = off;
    off += (k + 1) * 4;
    l.counts = off;
    off += k * 4;
    l.labels = off;
    off += tb * BLOCK;
    off = align_up(off, 2);
    l.blocks = off;
    off += tb * DIMS * BLOCK * 2;
    l.total = off;
    l
}

/// Offset (em unidades de i16) dentro do array [i16; DIMS*BLOCK] de um bloco,
/// para (dimensão d, lane). Layout pair-SoA: (d/2)*BLOCK*2 + lane*2 + (d&1).
#[inline]
pub fn block_pair_offset(d: usize, lane: usize) -> usize {
    (d / 2) * BLOCK * 2 + lane * 2 + (d & 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_is_64_bytes() {
        assert_eq!(core::mem::size_of::<IndexHeader>(), 64);
    }

    #[test]
    fn layout_offsets() {
        let l = layout_for(8, 2);
        assert_eq!(l.centroids, 64);
        assert_eq!(l.bbox_min, 64 + 8 * DIMS * 2);
        assert_eq!(l.bbox_max, 64 + 2 * 8 * DIMS * 2);
        // offsets aligned to 4 after 3 i16 sections (each 8*14*2 = 224, total 672, +64 = 736, /4 ok)
        assert_eq!(l.offsets % 4, 0);
        assert!(l.total > l.blocks);
    }

    #[test]
    fn pair_offsets() {
        assert_eq!(block_pair_offset(0, 0), 0);
        assert_eq!(block_pair_offset(1, 0), 1);
        assert_eq!(block_pair_offset(0, 1), 2);
        assert_eq!(block_pair_offset(2, 0), BLOCK * 2);
        assert_eq!(block_pair_offset(13, 7), 6 * BLOCK * 2 + 7 * 2 + 1);
    }
}
