use crate::{
    codecs::{
        av1::parse_av1_payload_header,
        avc::{avc_vcl_type, parse_avc_payload_header, AvcNalKind},
        hevc::{hevc_vcl_type, parse_hevc_payload_header, HevcNalKind},
        vp9::Vp9PayloadDesc,
        Codec,
    },
    guess::guess_codec,
    rtp::RtpPacket,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameBoundary {
    None,
    Start,
    End,
    StartEnd,
}

#[derive(Debug, Default)]
pub struct FrameAnalyzer {
    codec: Option<Codec>,
    in_frame: bool,
}

impl FrameAnalyzer {
    pub fn new() -> Self {
        Self {
            codec: None,
            in_frame: false,
        }
    }

    pub fn set_codec(&mut self, codec: Codec) {
        self.codec = Some(codec);
    }

    pub fn codec(&self) -> Option<Codec> {
        self.codec
    }

    pub fn analyze<'a>(&mut self, packet: &RtpPacket<'a>) -> FrameBoundary {
        // Guess codec if unknown
        let codec = self.codec.unwrap_or_else(|| guess_codec(packet.payload));
        self.codec = Some(codec);

        match codec {
            Codec::Avc => self.analyze_avc(packet),
            Codec::Hevc => self.analyze_hevc(packet),
            Codec::Vp9 => self.analyze_vp9(packet),
            Codec::Av1 => self.analyze_av1(packet),
            Codec::Unknown => self.analyze_generic(packet),
        }
    }

    fn analyze_generic(&mut self, packet: &RtpPacket<'_>) -> FrameBoundary {
        // Generic: use RTP marker bit boundaries
        let start = !self.in_frame;
        let end = packet.header.marker;
        self.in_frame = !end;
        match (start, end) {
            (true, true) => FrameBoundary::StartEnd,
            (true, false) => FrameBoundary::Start,
            (false, true) => FrameBoundary::End,
            _ => FrameBoundary::None,
        }
    }

    fn analyze_avc(&mut self, packet: &RtpPacket<'_>) -> FrameBoundary {
        let (kind, _off) = match parse_avc_payload_header(packet.payload) {
            Ok(v) => v,
            Err(_) => return self.analyze_generic(packet),
        };
        match kind {
            AvcNalKind::FuA {
                start: s,
                end: _e,
                nal_type,
            }
            | AvcNalKind::FuB {
                start: s,
                end: _e,
                nal_type,
            } => {
                let start = s && avc_vcl_type(nal_type);
                let end = packet.header.marker;
                let fb = match (start, end) {
                    (true, true) => FrameBoundary::StartEnd,
                    (true, false) => FrameBoundary::Start,
                    (false, true) => FrameBoundary::End,
                    _ => FrameBoundary::None,
                };
                self.in_frame = !matches!(fb, FrameBoundary::End | FrameBoundary::StartEnd);
                fb
            }
            AvcNalKind::Single(t) => {
                let start = avc_vcl_type(t) && !self.in_frame;
                let end = packet.header.marker;
                let fb = match (start, end) {
                    (true, true) => FrameBoundary::StartEnd,
                    (true, false) => FrameBoundary::Start,
                    (false, true) => FrameBoundary::End,
                    _ => FrameBoundary::None,
                };
                self.in_frame = !matches!(fb, FrameBoundary::End | FrameBoundary::StartEnd);
                fb
            }
            AvcNalKind::StapA | AvcNalKind::StapB | AvcNalKind::Mtap16 | AvcNalKind::Mtap24 => {
                let start = !self.in_frame; // conservative
                let end = packet.header.marker;
                let fb = match (start, end) {
                    (true, true) => FrameBoundary::StartEnd,
                    (true, false) => FrameBoundary::Start,
                    (false, true) => FrameBoundary::End,
                    _ => FrameBoundary::None,
                };
                self.in_frame = !matches!(fb, FrameBoundary::End | FrameBoundary::StartEnd);
                fb
            }
            AvcNalKind::Unknown(_) => {
                let start = !self.in_frame;
                let end = packet.header.marker;
                let fb = match (start, end) {
                    (true, true) => FrameBoundary::StartEnd,
                    (true, false) => FrameBoundary::Start,
                    (false, true) => FrameBoundary::End,
                    _ => FrameBoundary::None,
                };
                self.in_frame = !matches!(fb, FrameBoundary::End | FrameBoundary::StartEnd);
                fb
            }
        }
    }

    fn analyze_hevc(&mut self, packet: &RtpPacket<'_>) -> FrameBoundary {
        let (kind, _off) = match parse_hevc_payload_header(packet.payload) {
            Ok(v) => v,
            Err(_) => return self.analyze_generic(packet),
        };
        match kind {
            HevcNalKind::Fu {
                start: s,
                end: _e,
                nal_type,
            } => {
                let start = s && hevc_vcl_type(nal_type);
                let end = packet.header.marker;
                let fb = match (start, end) {
                    (true, true) => FrameBoundary::StartEnd,
                    (true, false) => FrameBoundary::Start,
                    (false, true) => FrameBoundary::End,
                    _ => FrameBoundary::None,
                };
                self.in_frame = !matches!(fb, FrameBoundary::End | FrameBoundary::StartEnd);
                fb
            }
            HevcNalKind::Single { nal_type } => {
                let start = hevc_vcl_type(nal_type) && !self.in_frame;
                let end = packet.header.marker;
                let fb = match (start, end) {
                    (true, true) => FrameBoundary::StartEnd,
                    (true, false) => FrameBoundary::Start,
                    (false, true) => FrameBoundary::End,
                    _ => FrameBoundary::None,
                };
                self.in_frame = !matches!(fb, FrameBoundary::End | FrameBoundary::StartEnd);
                fb
            }
            HevcNalKind::Ap | HevcNalKind::Pacsi | HevcNalKind::Unknown(_) => {
                let start = !self.in_frame;
                let end = packet.header.marker;
                let fb = match (start, end) {
                    (true, true) => FrameBoundary::StartEnd,
                    (true, false) => FrameBoundary::Start,
                    (false, true) => FrameBoundary::End,
                    _ => FrameBoundary::None,
                };
                self.in_frame = !matches!(fb, FrameBoundary::End | FrameBoundary::StartEnd);
                fb
            }
        }
    }

    fn analyze_vp9(&mut self, packet: &RtpPacket<'_>) -> FrameBoundary {
        let (desc, _off) = match Vp9PayloadDesc::parse(packet.payload) {
            Ok(v) => v,
            Err(_) => return self.analyze_generic(packet),
        };
        let start = desc.b_bit || !self.in_frame;
        let end = desc.e_bit || packet.header.marker;
        let fb = match (start, end) {
            (true, true) => FrameBoundary::StartEnd,
            (true, false) => FrameBoundary::Start,
            (false, true) => FrameBoundary::End,
            _ => FrameBoundary::None,
        };
        self.in_frame = !matches!(fb, FrameBoundary::End | FrameBoundary::StartEnd);
        fb
    }

    fn analyze_av1(&mut self, packet: &RtpPacket<'_>) -> FrameBoundary {
        // Minimal parse to ensure it's AV1; otherwise generic
        let _ = match parse_av1_payload_header(packet.payload) {
            Ok(v) => v,
            Err(_) => return self.analyze_generic(packet),
        };
        let start = !self.in_frame; // assume new packet after frame end starts a frame
        let end = packet.header.marker; // AV1 uses marker to signal last packet of frame
        let fb = match (start, end) {
            (true, true) => FrameBoundary::StartEnd,
            (true, false) => FrameBoundary::Start,
            (false, true) => FrameBoundary::End,
            _ => FrameBoundary::None,
        };
        self.in_frame = !matches!(fb, FrameBoundary::End | FrameBoundary::StartEnd);
        fb
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::RtpPacket;

    fn build_rtp(payload: &[u8], marker: bool) -> Vec<u8> {
        let mut v = Vec::new();
        let b0 = (2u8 << 6) | 0;
        v.push(b0);
        let mut b1 = 96u8;
        if marker {
            b1 |= 0x80;
        }
        v.push(b1);
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&2u32.to_be_bytes());
        v.extend_from_slice(&3u32.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn h264_fu_frame_boundaries() {
        let mut a = FrameAnalyzer::new();
        a.set_codec(Codec::Avc);
        // FU-A S=1
        let p1 = build_rtp(&[0x1C, 0x80 | 0x01, 0xAA, 0xBB], false);
        let pkt1 = RtpPacket::parse(&p1).unwrap();
        assert_eq!(a.analyze(&pkt1), FrameBoundary::Start);
        // middle FU-A
        let p2 = build_rtp(&[0x1C, 0x00 | 0x01, 0xCC], false);
        let pkt2 = RtpPacket::parse(&p2).unwrap();
        assert_eq!(a.analyze(&pkt2), FrameBoundary::None);
        // end FU-A, marker set
        let p3 = build_rtp(&[0x1C, 0x40 | 0x01, 0xDD], true);
        let pkt3 = RtpPacket::parse(&p3).unwrap();
        assert_eq!(a.analyze(&pkt3), FrameBoundary::End);
    }

    #[test]
    fn h265_fu_frame_boundaries() {
        let mut a = FrameAnalyzer::new();
        a.set_codec(Codec::Hevc);
        // HEVC FU start
        let p1 = build_rtp(&[((49u8 << 1) & 0x7E), 0x01, 0x80 | 0x01], false);
        let pkt1 = RtpPacket::parse(&p1).unwrap();
        assert_eq!(a.analyze(&pkt1), FrameBoundary::Start);
        // HEVC FU end with marker
        let p2 = build_rtp(&[((49u8 << 1) & 0x7E), 0x01, 0x40 | 0x01], true);
        let pkt2 = RtpPacket::parse(&p2).unwrap();
        assert_eq!(a.analyze(&pkt2), FrameBoundary::End);
    }

    #[test]
    fn vp9_b_e_bits() {
        let mut a = FrameAnalyzer::new();
        a.set_codec(Codec::Vp9);
        // VP9: I=1, B=1 start of frame, PictureID 7-bit
        let p1 = build_rtp(&[0x80 | 0x08, 0x0A], false);
        let pkt1 = RtpPacket::parse(&p1).unwrap();
        assert_eq!(a.analyze(&pkt1), FrameBoundary::Start);
        // VP9: E=1 end of frame
        let p2 = build_rtp(&[0x04 /*E*/], true);
        let pkt2 = RtpPacket::parse(&p2).unwrap();
        assert_eq!(a.analyze(&pkt2), FrameBoundary::End);
    }

    #[test]
    fn av1_marker_end() {
        let mut a = FrameAnalyzer::new();
        a.set_codec(Codec::Av1);
        // First packet of a frame (start assumed when out-of-frame)
        let p1 = build_rtp(&[0x04], false);
        let pkt1 = RtpPacket::parse(&p1).unwrap();
        assert_eq!(a.analyze(&pkt1), FrameBoundary::Start);
        // middle packet
        let p2 = build_rtp(&[0x04], false);
        let pkt2 = RtpPacket::parse(&p2).unwrap();
        assert_eq!(a.analyze(&pkt2), FrameBoundary::None);
        // last packet with marker
        let p3 = build_rtp(&[0x04], true);
        let pkt3 = RtpPacket::parse(&p3).unwrap();
        assert_eq!(a.analyze(&pkt3), FrameBoundary::End);
    }
}
