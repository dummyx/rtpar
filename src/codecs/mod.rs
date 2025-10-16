pub mod av1;
pub mod avc;
pub mod hevc;
pub mod vp9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    Vp9,
    Avc,
    Hevc,
    Av1,
    Unknown,
}
