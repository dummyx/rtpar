use crate::codecs::Codec;

pub fn guess_codec(payload: &[u8]) -> Codec {
    if payload.is_empty() {
        return Codec::Unknown;
    }

    let b0 = payload[0];

    // Try HEVC (H.265) first, but conservatively: only identify FU (type=49) when FU header present.
    if payload.len() >= 3 {
        let hevc_type = (b0 & 0x7E) >> 1;
        if hevc_type == 49 {
            let fu_hdr = payload[2];
            if (fu_hdr & 0x80) != 0 || (fu_hdr & 0x40) != 0 {
                // S or E set
                return Codec::Hevc;
            }
        }
    }

    // Try AV1: first octet's two LSBs are reserved and should be zero.
    if (b0 & 0x03) == 0 {
        return Codec::Av1;
    }

    // Try AVC (H.264): Single NAL (1..23) or FU/aggregation (24..29)
    let avc_type = b0 & 0x1F;
    let avc_nri_nonzero = (b0 & 0x60) != 0; // NRI bits (importance) should be non-zero in typical H.264 RTP
    if (24..=29).contains(&avc_type) {
        if payload.len() >= 2 && avc_nri_nonzero {
            return Codec::Avc;
        }
    } else if (1..=23).contains(&avc_type) && avc_nri_nonzero {
        return Codec::Avc;
    }

    // Fallback to VP9
    Codec::Vp9
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guess_avc_h264() {
        let payload = [0x65, 0x00, 0x00]; // type=5 IDR
        assert_eq!(guess_codec(&payload), Codec::Avc);
    }

    #[test]
    fn guess_hevc_h265_fu() {
        let payload = [(49u8 << 1) & 0x7E, 0x01, 0x80]; // FU
        assert_eq!(guess_codec(&payload), Codec::Hevc);
    }

    #[test]
    fn guess_av1_vs_vp9() {
        let av1_payload = [0x04, 0xAA]; // AV1 first byte with reserved bits zero (0x04 ends with 00)
        let vp9_payload = [0x07, 0x80]; // LSBs not both zero -> VP9 by heuristic
        assert_eq!(guess_codec(&av1_payload), Codec::Av1);
        assert_eq!(guess_codec(&vp9_payload), Codec::Vp9);
    }
}
