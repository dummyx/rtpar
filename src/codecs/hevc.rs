#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HevcNalKind {
    Single {
        nal_type: u8,
    },
    Ap, // Aggregation Packet (type 48)
    Fu {
        start: bool,
        end: bool,
        nal_type: u8,
    }, // Fragmentation Unit (type 49)
    Pacsi, // (type 50)
    Unknown(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HevcError {
    BufferTooShort,
}

#[inline]
pub fn hevc_vcl_type(nal_type: u8) -> bool {
    nal_type <= 31
}

pub fn parse_hevc_payload_header(payload: &[u8]) -> Result<(HevcNalKind, usize), HevcError> {
    if payload.len() < 2 {
        return Err(HevcError::BufferTooShort);
    }
    // HEVC NALU header is 2 bytes
    let b0 = payload[0];
    let nal_type = (b0 & 0x7E) >> 1; // 6 bits
    match nal_type {
        48 => Ok((HevcNalKind::Ap, 2)),
        49 => {
            if payload.len() < 3 {
                return Err(HevcError::BufferTooShort);
            }
            let fu_header = payload[2];
            let start = (fu_header & 0x80) != 0;
            let end = (fu_header & 0x40) != 0;
            let orig_type = fu_header & 0x3F;
            Ok((
                HevcNalKind::Fu {
                    start,
                    end,
                    nal_type: orig_type,
                },
                3,
            ))
        }
        50 => Ok((HevcNalKind::Pacsi, 2)),
        t @ 0..=47 | t @ 51..=63 => Ok((HevcNalKind::Single { nal_type: t }, 0)),
        t => Ok((HevcNalKind::Unknown(t), 0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hevc_fu_header() {
        // Construct a minimal FU header: NAL header with type=49, then FU header with S=1,E=0,type=1
        let b0 = (49u8 << 1) & 0x7E; // forbidden_zero_bit=0 and nal_type in bits 1..6
        let header = [b0, 0x01]; // second header byte arbitrary low value
        let fu = 0x80 | 0x01; // S=1, type=1
        let mut payload = Vec::new();
        payload.extend_from_slice(&header);
        payload.push(fu);
        let (kind, off) = parse_hevc_payload_header(&payload).unwrap();
        match kind {
            HevcNalKind::Fu {
                start,
                end,
                nal_type,
            } => {
                assert!(start);
                assert!(!end);
                assert_eq!(nal_type, 1);
            }
            _ => panic!(),
        }
        assert_eq!(off, 3);
    }
}
