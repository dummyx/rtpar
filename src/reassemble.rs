use crate::{
    analyze::FrameAnalyzer,
    codecs::{
        av1::parse_av1_payload_header,
        avc::{parse_avc_payload_header, AvcNalKind},
        hevc::{parse_hevc_payload_header, HevcNalKind},
        vp9::Vp9PayloadDesc,
        Codec,
    },
    rtp::RtpPacket,
};
use std::collections::{BTreeMap, HashMap};

#[derive(Debug, Default)]
pub struct FrameReassembler {
    analyzer: FrameAnalyzer,
    current_ssrc: Option<u32>,
    codec: Option<Codec>,
    frames: HashMap<u32, FrameCollector>,
    config: ReorderConfig,
}

#[derive(Debug, Clone, Copy)]
pub struct ReorderConfig {
    pub enable_reordering: bool,
    pub drop_incomplete_frames: bool,
    pub max_buffered_packets_per_frame: usize,
}

impl Default for ReorderConfig {
    fn default() -> Self {
        Self {
            enable_reordering: true,
            drop_incomplete_frames: true,
            max_buffered_packets_per_frame: 2048,
        }
    }
}

#[derive(Debug, Default)]
struct FrameCollector {
    packets: BTreeMap<u16, OwnedPkt>,
    seen_marker: bool,
}

#[derive(Debug, Clone)]
struct OwnedPkt {
    seq: u16,
    payload: Vec<u8>,
}

impl FrameReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_codec(&mut self, codec: Codec) {
        self.codec = Some(codec);
        self.analyzer.set_codec(codec);
    }

    pub fn codec(&self) -> Option<Codec> {
        self.codec
    }

    pub fn set_reorder_config(&mut self, cfg: ReorderConfig) {
        self.config = cfg;
    }

    // Push a parsed RTP packet. Returns Some(frame_bytes) when a full frame is completed.
    pub fn push_packet<'a>(&mut self, pkt: &RtpPacket<'a>) -> Option<Vec<u8>> {
        // Reset on SSRC change
        if let Some(ssrc) = self.current_ssrc {
            if ssrc != pkt.header.ssrc {
                self.frames.clear();
                self.analyzer = FrameAnalyzer::new();
                if let Some(c) = self.codec {
                    self.analyzer.set_codec(c);
                }
            }
        }
        self.current_ssrc = Some(pkt.header.ssrc);

        // Update analyzer for codec guess tracking
        let _ = self.analyzer.analyze(pkt);
        if self.codec.is_none() {
            self.codec = self.analyzer.codec();
        }

        // Insert packet into frame map keyed by RTP timestamp
        let ts = pkt.header.timestamp;
        let entry = self.frames.entry(ts).or_default();
        if entry.packets.len() >= self.config.max_buffered_packets_per_frame {
            entry.packets.clear();
        }
        let owned = OwnedPkt { seq: pkt.header.sequence_number, payload: pkt.payload.to_vec() };
        entry.packets.insert(owned.seq, owned);
        if pkt.header.marker {
            entry.seen_marker = true;
        }

        // If marker received for this frame, attempt to assemble and flush only when start conditions are present (for reordering)
        if entry.seen_marker {
            let codec = self.codec.unwrap_or(Codec::Unknown);
            if self.frame_ready_to_flush(ts, codec) {
                let out = self.assemble_frame(ts);
                self.frames.remove(&ts);
                return out;
            }
        }
        None
    }

    fn frame_ready_to_flush(&self, timestamp: u32, codec: Codec) -> bool {
        let entry = match self.frames.get(&timestamp) {
            Some(e) => e,
            None => return false,
        };
        if !entry.seen_marker {
            return false;
        }
        match codec {
            Codec::Avc => {
                for (_seq, pkt) in entry.packets.iter() {
                    if let Ok((kind, _off)) = parse_avc_payload_header(&pkt.payload) {
                        match kind {
                            AvcNalKind::Single(_)
                            | AvcNalKind::StapA
                            | AvcNalKind::StapB
                            | AvcNalKind::Mtap16
                            | AvcNalKind::Mtap24 => return true,
                            AvcNalKind::FuA { start, .. } | AvcNalKind::FuB { start, .. } => {
                                if start {
                                    return true;
                                }
                            }
                            AvcNalKind::Unknown(_) => {}
                        }
                    }
                }
                false
            }
            Codec::Hevc => {
                for (_seq, pkt) in entry.packets.iter() {
                    if let Ok((kind, _off)) = parse_hevc_payload_header(&pkt.payload) {
                        match kind {
                            HevcNalKind::Single { .. } | HevcNalKind::Ap | HevcNalKind::Pacsi => {
                                return true
                            }
                            HevcNalKind::Fu { start, .. } => {
                                if start {
                                    return true;
                                }
                            }
                            HevcNalKind::Unknown(_) => {}
                        }
                    }
                }
                false
            }
            Codec::Vp9 => {
                for (_seq, pkt) in entry.packets.iter() {
                    if let Ok((desc, _)) = Vp9PayloadDesc::parse(&pkt.payload) {
                        if desc.b_bit {
                            return true;
                        }
                    }
                }
                false
            }
            Codec::Av1 | Codec::Unknown => true,
        }
    }

    fn assemble_frame(&mut self, timestamp: u32) -> Option<Vec<u8>> {
        let codec = self.codec.unwrap_or(Codec::Unknown);
        let entry = self.frames.get(&timestamp)?;
        let mut incomplete = false;
        let mut out = Vec::new();

        // Track FU start presence
        let mut fu_open_avc = false;
        let mut fu_open_hevc = false;

        // Detect sequence gaps (simple increasing u16, wrap not fully handled)
        let mut last_seq: Option<u16> = None;
        for (&seq, _) in entry.packets.iter() {
            if let Some(last) = last_seq {
                if seq.wrapping_sub(last) != 1 {
                    incomplete = true;
                }
            }
            last_seq = Some(seq);
        }

        for (_seq, pkt) in entry.packets.iter() {
            match codec {
                Codec::Avc => Self::append_avc_payload(
                    &pkt.payload,
                    &mut out,
                    &mut fu_open_avc,
                    &mut incomplete,
                ),
                Codec::Hevc => Self::append_hevc_payload(
                    &pkt.payload,
                    &mut out,
                    &mut fu_open_hevc,
                    &mut incomplete,
                ),
                Codec::Vp9 => Self::append_vp9_payload(&pkt.payload, &mut out),
                Codec::Av1 => Self::append_av1_payload(&pkt.payload, &mut out),
                Codec::Unknown => out.extend_from_slice(&pkt.payload),
            }
        }

        if self.config.drop_incomplete_frames && incomplete {
            return None;
        }
        Some(out)
    }

    fn write_start_code(buf: &mut Vec<u8>) {
        buf.extend_from_slice(&[0, 0, 0, 1]);
    }

    fn append_avc_payload(
        payload: &[u8],
        out: &mut Vec<u8>,
        fu_open: &mut bool,
        incomplete: &mut bool,
    ) {
        if let Ok((kind, off)) = parse_avc_payload_header(payload) {
            match kind {
                AvcNalKind::Single(_) => {
                    Self::write_start_code(out);
                    out.extend_from_slice(&payload[0..]);
                }
                AvcNalKind::StapA => {
                    // STAP-A: 1-byte indicator then series of (16-bit size, nalu)
                    let mut i = 1usize; // skip indicator
                    while i + 2 <= payload.len() {
                        let size = u16::from_be_bytes([payload[i], payload[i + 1]]) as usize;
                        i += 2;
                        if i + size > payload.len() {
                            break;
                        }
                        Self::write_start_code(out);
                        out.extend_from_slice(&payload[i..i + size]);
                        i += size;
                    }
                }
                AvcNalKind::FuA {
                    start,
                    end: _,
                    nal_type,
                }
                | AvcNalKind::FuB {
                    start,
                    end: _,
                    nal_type,
                } => {
                    if start {
                        // Reconstruct NAL header: take F and NRI from FU indicator, payload type from FU header
                        let fu_indicator = payload[0];
                        let nal_hdr = (fu_indicator & 0xE0) | (nal_type & 0x1F);
                        Self::write_start_code(out);
                        out.push(nal_hdr);
                        *fu_open = true;
                    } else if !*fu_open {
                        *incomplete = true;
                        return;
                    }
                    out.extend_from_slice(&payload[off..]);
                }
                AvcNalKind::StapB
                | AvcNalKind::Mtap16
                | AvcNalKind::Mtap24
                | AvcNalKind::Unknown(_) => {
                    // Fallback: copy as single NAL (best-effort)
                    Self::write_start_code(out);
                    out.extend_from_slice(payload);
                }
            }
        } else {
            // Unknown/invalid, just append raw
            out.extend_from_slice(payload);
        }
    }

    fn append_hevc_payload(
        payload: &[u8],
        out: &mut Vec<u8>,
        fu_open: &mut bool,
        incomplete: &mut bool,
    ) {
        if let Ok((kind, off)) = parse_hevc_payload_header(payload) {
            match kind {
                HevcNalKind::Single { .. } | HevcNalKind::Pacsi | HevcNalKind::Unknown(_) => {
                    Self::write_start_code(out);
                    out.extend_from_slice(&payload[0..]);
                }
                HevcNalKind::Ap => {
                    // AP: after 2-byte header, sequence of 16-bit length + NALU
                    let mut i = 2usize; // skip AP header (nal header with type=48)
                    while i + 2 <= payload.len() {
                        let size = u16::from_be_bytes([payload[i], payload[i + 1]]) as usize;
                        i += 2;
                        if i + size > payload.len() {
                            break;
                        }
                        Self::write_start_code(out);
                        out.extend_from_slice(&payload[i..i + size]);
                        i += size;
                    }
                }
                HevcNalKind::Fu {
                    start,
                    end: _,
                    nal_type,
                } => {
                    if start {
                        // Reconstruct 2-byte NAL header by replacing type bits
                        let b0 = payload[0];
                        let b1 = payload[1];
                        let new_b0 = (b0 & !0x7E) | ((nal_type << 1) & 0x7E);
                        Self::write_start_code(out);
                        out.push(new_b0);
                        out.push(b1);
                        *fu_open = true;
                    } else if !*fu_open {
                        *incomplete = true;
                        return;
                    }
                    out.extend_from_slice(&payload[off..]);
                }
            }
        } else {
            out.extend_from_slice(payload);
        }
    }

    fn append_vp9_payload(payload: &[u8], out: &mut Vec<u8>) {
        if let Ok((_desc, off)) = Vp9PayloadDesc::parse(payload) {
            out.extend_from_slice(&payload[off..]);
        } else {
            out.extend_from_slice(payload);
        }
    }

    fn append_av1_payload(payload: &[u8], out: &mut Vec<u8>) {
        if let Ok((_hdr, off)) = parse_av1_payload_header(payload) {
            out.extend_from_slice(&payload[off..]);
        } else {
            out.extend_from_slice(payload);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::RtpPacket;

    fn build_rtp_with_seq(payload: &[u8], marker: bool, seq: u16) -> Vec<u8> {
        let mut v = Vec::new();
        let b0 = (2u8 << 6) | 0;
        v.push(b0);
        let mut b1 = 96u8;
        if marker {
            b1 |= 0x80;
        }
        v.push(b1);
        v.extend_from_slice(&seq.to_be_bytes());
        v.extend_from_slice(&2u32.to_be_bytes());
        v.extend_from_slice(&3u32.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn reassemble_h264_fu_annexb() {
        let mut r = FrameReassembler::new();
        r.set_codec(Codec::Avc);
        // FU-A S=1, type=5 (IDR), indicator with NRI=0x60
        let p1 = build_rtp_with_seq(
            &[0x7C /*28 + NRI=0x60*/, 0x80 | 0x05, 0xAA, 0xBB],
            false,
            100,
        );
        let p2 = build_rtp_with_seq(&[0x7C, 0x00 | 0x05, 0xCC], true, 101);
        let pkt1 = RtpPacket::parse(&p1).unwrap();
        let pkt2 = RtpPacket::parse(&p2).unwrap();
        assert!(r.push_packet(&pkt1).is_none());
        let out = r.push_packet(&pkt2).expect("frame");
        // Expect start code + [reconstructed header] + payload fragments
        assert!(out.starts_with(&[0, 0, 0, 1]));
        // reconstructed nal header should be 0xE0 (F/NRI) from indicator + 0x05 type -> 0x65 typical
        assert_eq!(out[4], 0x65);
        assert_eq!(&out[5..], &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn reassemble_h264_stap_a() {
        let mut r = FrameReassembler::new();
        r.set_codec(Codec::Avc);
        // STAP-A: indicator 24, then len1=2, nalu1(0x61,0x01), len2=3, nalu2(0x65,0x02,0x03)
        let payload = [0x18, 0x00, 0x02, 0x61, 0x01, 0x00, 0x03, 0x65, 0x02, 0x03];
        let p = build_rtp_with_seq(&payload, true, 200);
        let pkt = RtpPacket::parse(&p).unwrap();
        let out = r.push_packet(&pkt).expect("frame");
        // Two start codes
        let sc = [0, 0, 0, 1];
        assert!(out.starts_with(&sc));
        let mut idx = 4;
        assert_eq!(&out[idx..idx + 2], &[0x61, 0x01]);
        idx += 2;
        assert_eq!(&out[idx..idx + 4], &sc);
        idx += 4;
        assert_eq!(&out[idx..idx + 3], &[0x65, 0x02, 0x03]);
    }

    #[test]
    fn reassemble_h265_fu_annexb() {
        let mut r = FrameReassembler::new();
        r.set_codec(Codec::Hevc);
        // HEVC FU: header bytes with type=49, then FU header S=1 type=19 (IDR_W_RADL typically)
        let b0 = (49u8 << 1) & 0x7E;
        let b1 = 0x01; // simple header
        let fu_s = 0x80 | 19u8; // S=1, type=19
        let fu_m = 0x00 | 19u8; // middle
        let p1 = build_rtp_with_seq(&[b0, b1, fu_s, 0xDE], false, 300);
        let p2 = build_rtp_with_seq(&[b0, b1, fu_m, 0xAD, 0xBE], true, 301);
        let pkt1 = RtpPacket::parse(&p1).unwrap();
        let pkt2 = RtpPacket::parse(&p2).unwrap();
        assert!(r.push_packet(&pkt1).is_none());
        let out = r.push_packet(&pkt2).expect("frame");
        assert!(out.starts_with(&[0, 0, 0, 1]));
        // reconstructed header first byte should have type=19
        let new_b0 = out[4];
        assert_eq!((new_b0 & 0x7E) >> 1, 19);
        assert_eq!(&out[6..], &[0xDE, 0xAD, 0xBE]);
    }

    #[test]
    fn reassemble_vp9_concat() {
        let mut r = FrameReassembler::new();
        r.set_codec(Codec::Vp9);
        // VP9: two fragments: first with B=1 I=1 and PictureID 7-bit=1, second with E=1
        let p1 = build_rtp_with_seq(&[0x80 | 0x08, 0x01, 0xAA], false, 400); // desc + payload 0xAA
        let p2 = build_rtp_with_seq(&[0x04, 0xBB, 0xCC], true, 401); // E=1
        let pkt1 = RtpPacket::parse(&p1).unwrap();
        let pkt2 = RtpPacket::parse(&p2).unwrap();
        assert!(r.push_packet(&pkt1).is_none());
        let out = r.push_packet(&pkt2).expect("frame");
        assert_eq!(&out, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn reassemble_av1_concat() {
        let mut r = FrameReassembler::new();
        r.set_codec(Codec::Av1);
        // AV1 header byte only then payloads
        let p1 = build_rtp_with_seq(&[0x04, 0xAA], false, 500);
        let p2 = build_rtp_with_seq(&[0x04, 0xBB, 0xCC], true, 501);
        let pkt1 = RtpPacket::parse(&p1).unwrap();
        let pkt2 = RtpPacket::parse(&p2).unwrap();
        assert!(r.push_packet(&pkt1).is_none());
        let out = r.push_packet(&pkt2).expect("frame");
        assert_eq!(&out, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn reorder_out_of_order_h264_fu() {
        let mut r = FrameReassembler::new();
        r.set_codec(Codec::Avc);
        // Send middle FU first with marker, then start FU
        let fu_mid = build_rtp_with_seq(&[0x7C, 0x00 | 0x05, 0x11], true, 610);
        let fu_start = build_rtp_with_seq(&[0x7C /*28+NRI*/, 0x80 | 0x05, 0x22, 0x33], false, 609);
        let pkt_mid = RtpPacket::parse(&fu_mid).unwrap();
        let pkt_start = RtpPacket::parse(&fu_start).unwrap();
        // First push (marker, but no start yet) should not flush due to reordering
        assert!(r.push_packet(&pkt_mid).is_none());
        // Now push start; should flush assembled, ordered by seq
        let out = r.push_packet(&pkt_start).expect("frame");
        assert!(out.starts_with(&[0, 0, 0, 1]));
        assert_eq!(out[4] & 0x1F, 0x05);
        assert_eq!(&out[5..], &[0x22, 0x33, 0x11]);
    }

    #[test]
    fn drop_incomplete_on_gap() {
        let mut r = FrameReassembler::new();
        r.set_codec(Codec::Avc);
        // Missing middle packet (gap between seq)
        let fu_start = build_rtp_with_seq(&[0x7C /*28+NRI*/, 0x80 | 0x01, 0xAA], false, 700);
        let fu_end = build_rtp_with_seq(&[0x7C, 0x40 | 0x01, 0xBB], true, 702);
        let pkt_s = RtpPacket::parse(&fu_start).unwrap();
        let pkt_e = RtpPacket::parse(&fu_end).unwrap();
        assert!(r.push_packet(&pkt_s).is_none());
        // End arrives, gap exists -> dropped (None)
        assert!(r.push_packet(&pkt_e).is_none());
    }

    #[test]
    fn reorder_out_of_order_vp9() {
        let mut r = FrameReassembler::new();
        r.set_codec(Codec::Vp9);
        // E=1 packet arrives first, then B=1 start
        let end_pkt = build_rtp_with_seq(&[0x04, 0xBB], true, 801);
        let start_pkt = build_rtp_with_seq(&[0x80 | 0x08, 0x01, 0xAA], false, 800);
        let pe = RtpPacket::parse(&end_pkt).unwrap();
        let ps = RtpPacket::parse(&start_pkt).unwrap();
        assert!(r.push_packet(&pe).is_none());
        let out = r.push_packet(&ps).expect("frame");
        assert_eq!(&out, &[0xAA, 0xBB]);
    }
}
