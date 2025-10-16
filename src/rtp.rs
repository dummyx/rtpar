#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpHeader {
    pub version: u8,
    pub padding: bool,
    pub extension: bool,
    pub csrc_count: u8,
    pub marker: bool,
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub csrcs: Vec<u32>,
    pub extension_header: Option<RtpExtension>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpExtension {
    pub profile: u16,
    pub length_words: u16,
    pub data_offset: usize,
    pub data_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpPacket<'a> {
    pub header: RtpHeader,
    pub payload_offset: usize,
    pub payload: &'a [u8],
}

#[derive(Debug, PartialEq, Eq)]
pub enum RtpError {
    BufferTooShort,
    InvalidVersion(u8),
    InvalidExtensionLength,
}

impl core::fmt::Display for RtpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RtpError::BufferTooShort => write!(f, "buffer too short"),
            RtpError::InvalidVersion(v) => write!(f, "invalid rtp version {}", v),
            RtpError::InvalidExtensionLength => write!(f, "invalid header extension length"),
        }
    }
}

impl std::error::Error for RtpError {}

impl<'a> RtpPacket<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<RtpPacket<'a>, RtpError> {
        if buf.len() < 12 {
            return Err(RtpError::BufferTooShort);
        }
        let b0 = buf[0];
        let version = (b0 >> 6) & 0x03;
        if version != 2 {
            return Err(RtpError::InvalidVersion(version));
        }
        let padding = ((b0 >> 5) & 0x01) != 0;
        let extension = ((b0 >> 4) & 0x01) != 0;
        let csrc_count = b0 & 0x0F;

        let b1 = buf[1];
        let marker = (b1 & 0x80) != 0;
        let payload_type = b1 & 0x7F;

        let sequence_number = u16::from_be_bytes([buf[2], buf[3]]);
        let timestamp = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let ssrc = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);

        let mut offset = 12usize;
        let mut csrcs = Vec::new();
        for _ in 0..csrc_count {
            if buf.len() < offset + 4 {
                return Err(RtpError::BufferTooShort);
            }
            csrcs.push(u32::from_be_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ]));
            offset += 4;
        }

        let mut extension_header = None;
        if extension {
            if buf.len() < offset + 4 {
                return Err(RtpError::BufferTooShort);
            }
            let profile = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            let length_words = u16::from_be_bytes([buf[offset + 2], buf[offset + 3]]);
            offset += 4;
            let ext_len_bytes = length_words as usize * 4;
            if buf.len() < offset + ext_len_bytes {
                return Err(RtpError::InvalidExtensionLength);
            }
            extension_header = Some(RtpExtension {
                profile,
                length_words,
                data_offset: offset,
                data_len: ext_len_bytes,
            });
            offset += ext_len_bytes;
        }

        // Remove padding at end if present
        let payload_end = if padding {
            // Last byte indicates number of padding octets including itself
            if buf.len() <= offset {
                return Err(RtpError::BufferTooShort);
            }
            let pad = *buf.last().unwrap() as usize;
            if pad == 0 || pad > buf.len() - offset {
                return Err(RtpError::BufferTooShort);
            }
            buf.len() - pad
        } else {
            buf.len()
        };

        let payload = &buf[offset..payload_end];
        Ok(RtpPacket {
            header: RtpHeader {
                version,
                padding,
                extension,
                csrc_count,
                marker,
                payload_type,
                sequence_number,
                timestamp,
                ssrc,
                csrcs,
                extension_header,
            },
            payload_offset: offset,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_basic_rtp(
        v: u8,
        p: bool,
        x: bool,
        cc: u8,
        m: bool,
        pt: u8,
        seq: u16,
        ts: u32,
        ssrc: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut b = Vec::new();
        let mut b0 = (v & 0x03) << 6;
        if p {
            b0 |= 1 << 5;
        }
        if x {
            b0 |= 1 << 4;
        }
        b0 |= cc & 0x0F;
        b.push(b0);
        let mut b1 = pt & 0x7F;
        if m {
            b1 |= 0x80;
        }
        b.push(b1);
        b.extend_from_slice(&seq.to_be_bytes());
        b.extend_from_slice(&ts.to_be_bytes());
        b.extend_from_slice(&ssrc.to_be_bytes());
        // No CSRCs
        // No extension
        b.extend_from_slice(payload);
        b
    }

    #[test]
    fn parse_basic_packet() {
        let payload = [1, 2, 3, 4, 5];
        let buf = build_basic_rtp(
            2, false, false, 0, true, 96, 1234, 0x11223344, 0x55667788, &payload,
        );
        let pkt = RtpPacket::parse(&buf).unwrap();
        assert_eq!(pkt.header.version, 2);
        assert!(pkt.header.marker);
        assert_eq!(pkt.header.payload_type, 96);
        assert_eq!(pkt.header.sequence_number, 1234);
        assert_eq!(pkt.header.timestamp, 0x11223344);
        assert_eq!(pkt.header.ssrc, 0x55667788);
        assert_eq!(pkt.payload, &payload);
    }

    #[test]
    fn parse_with_extension_and_padding() {
        // Build a packet with one CSRC, an extension of 2 words (8 bytes), and 4 bytes padding
        let mut buf = Vec::new();
        let v = 2;
        let p = true;
        let x = true;
        let cc = 1u8;
        let m = false;
        let pt = 111u8;
        let mut b0 = (v & 0x03) << 6;
        if p {
            b0 |= 1 << 5;
        }
        if x {
            b0 |= 1 << 4;
        }
        b0 |= cc;
        buf.push(b0);
        let mut b1 = pt & 0x7F;
        if m {
            b1 |= 0x80;
        }
        buf.push(b1);
        buf.extend_from_slice(&100u16.to_be_bytes()); // seq
        buf.extend_from_slice(&0xAABBCCDDu32.to_be_bytes()); // ts
        buf.extend_from_slice(&0x03040506u32.to_be_bytes()); // ssrc
                                                             // 1 CSRC
        buf.extend_from_slice(&0x0A0B0C0Du32.to_be_bytes());
        // Extension header (profile 0xBEDE, 2 words)
        buf.extend_from_slice(&0xBEDEu16.to_be_bytes());
        buf.extend_from_slice(&2u16.to_be_bytes());
        // 8 bytes extension data
        buf.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7]);
        // Payload (3 bytes)
        buf.extend_from_slice(&[9, 9, 9]);
        // Padding: 4 bytes of value 4 at the end
        buf.extend_from_slice(&[0, 0, 0, 4]);

        let pkt = RtpPacket::parse(&buf).unwrap();
        assert_eq!(pkt.header.version, 2);
        assert!(pkt.header.extension);
        assert!(pkt.header.padding);
        assert_eq!(pkt.header.csrcs.len(), 1);
        let ext = pkt.header.extension_header.as_ref().unwrap();
        assert_eq!(ext.profile, 0xBEDE);
        assert_eq!(ext.length_words, 2);
        assert_eq!(pkt.payload, &[9, 9, 9]);
    }
}
