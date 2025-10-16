#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Av1PayloadHdr {
    pub z_bit: bool,
    pub y_bit: bool,
    pub n_bit: bool,
    pub w_bit: bool,
    pub t_bit: bool,
    pub k_bit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Av1Error {
    BufferTooShort,
}

// Parse the minimal AV1 RTP payload header as per RFC 9364 first octet
pub fn parse_av1_payload_header(payload: &[u8]) -> Result<(Av1PayloadHdr, usize), Av1Error> {
    if payload.is_empty() {
        return Err(Av1Error::BufferTooShort);
    }
    let b0 = payload[0];
    let hdr = Av1PayloadHdr {
        z_bit: (b0 & 0x80) != 0,
        y_bit: (b0 & 0x40) != 0,
        n_bit: (b0 & 0x20) != 0,
        w_bit: (b0 & 0x10) != 0,
        t_bit: (b0 & 0x08) != 0,
        k_bit: (b0 & 0x04) != 0,
    };
    Ok((hdr, 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_av1_header_basic() {
        let b0 = 0x04; // K=1
        let (h, off) = parse_av1_payload_header(&[b0, 0xAA]).unwrap();
        assert!(h.k_bit);
        assert!(!h.t_bit);
        assert_eq!(off, 1);
    }
}
