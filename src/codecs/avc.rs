#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvcNalKind {
    // Single NAL unit (types 1..23)
    Single(u8),
    // Aggregation packet: STAP-A (24), STAP-B (25), MTAP16 (26), MTAP24 (27)
    StapA,
    StapB,
    Mtap16,
    Mtap24,
    // Fragmentation unit FU-A (28), FU-B (29)
    FuA {
        start: bool,
        end: bool,
        nal_type: u8,
    },
    FuB {
        start: bool,
        end: bool,
        nal_type: u8,
    },
    // Unsupported/unknown
    Unknown(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvcError {
    BufferTooShort,
}

#[inline]
pub fn avc_vcl_type(nal_type: u8) -> bool {
    (1..=5).contains(&nal_type)
}

pub fn parse_avc_payload_header(payload: &[u8]) -> Result<(AvcNalKind, usize), AvcError> {
    if payload.is_empty() {
        return Err(AvcError::BufferTooShort);
    }
    let indicator = payload[0];
    let nal_type = indicator & 0x1F;
    match nal_type {
        1..=23 => Ok((AvcNalKind::Single(nal_type), 0)), // no extra header beyond NAL itself
        24 => Ok((AvcNalKind::StapA, 1)),
        25 => Ok((AvcNalKind::StapB, 1)),
        26 => Ok((AvcNalKind::Mtap16, 1)),
        27 => Ok((AvcNalKind::Mtap24, 1)),
        28 | 29 => {
            if payload.len() < 2 {
                return Err(AvcError::BufferTooShort);
            }
            let fu_header = payload[1];
            let start = (fu_header & 0x80) != 0;
            let end = (fu_header & 0x40) != 0;
            let nt = fu_header & 0x1F;
            let kind = if nal_type == 28 {
                AvcNalKind::FuA {
                    start,
                    end,
                    nal_type: nt,
                }
            } else {
                AvcNalKind::FuB {
                    start,
                    end,
                    nal_type: nt,
                }
            };
            Ok((kind, 2))
        }
        t => Ok((AvcNalKind::Unknown(t), 0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_fu_a_header() {
        // FU indicator type=28, FU header S=1,E=0, type=1
        let payload = [0x1C /*28*/, 0x80 | 0x01];
        let (kind, off) = parse_avc_payload_header(&payload).unwrap();
        match kind {
            AvcNalKind::FuA {
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
        assert_eq!(off, 2);
    }

    #[test]
    fn parse_single_nal() {
        let payload = [
            0x65, /*IDR type=5 with NRI bits would be 0x65 typically*/
        ];
        let (kind, off) = parse_avc_payload_header(&payload).unwrap();
        match kind {
            AvcNalKind::Single(t) => assert_eq!(t, 5),
            _ => panic!(),
        }
        assert_eq!(off, 0);
    }
}
