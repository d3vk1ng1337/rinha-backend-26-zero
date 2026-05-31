//! Núcleo do índice IVF: formato pair-SoA, quantização int16, normalização
//! 14-dim e busca. Portado fielmente do pipeline f32 que crava accuracy 6000
//! (ver docs/specs). Sem dependências — usado pelo servidor no hot path.

pub mod format;
pub mod normalize;
pub mod quant;
pub mod search;
