#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Vp9PayloadDesc {
    pub i_bit: bool,
    pub p_bit: bool,
    pub l_bit: bool,
    pub f_bit: bool,
    pub b_bit: bool,
    pub e_bit: bool,
    pub v_bit: bool,
    pub z_bit: bool,
    pub picture_id: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Vp9Error {
    BufferTooShort,
}

impl Vp9PayloadDesc {
    // Parses the VP9 payload descriptor as per RFC 8585.
    pub fn parse(buf: &[u8]) -> Result<(Self, usize), Vp9Error> {
        if buf.is_empty() {
            return Err(Vp9Error::BufferTooShort);
        }
        let b0 = buf[0];
        let i_bit = (b0 & 0x80) != 0;
        let p_bit = (b0 & 0x40) != 0;
        let l_bit = (b0 & 0x20) != 0;
        let f_bit = (b0 & 0x10) != 0;
        let b_bit = (b0 & 0x08) != 0;
        let e_bit = (b0 & 0x04) != 0;
        let v_bit = (b0 & 0x02) != 0;
        let z_bit = (b0 & 0x01) != 0;
        let mut offset = 1usize;
        let mut picture_id = None;
        if i_bit {
            if buf.len() < offset + 1 {
                return Err(Vp9Error::BufferTooShort);
            }
            let b = buf[offset];
            let m = (b & 0x80) != 0;
            let mut pid = (b & 0x7F) as u16;
            offset += 1;
            if m {
                if buf.len() < offset + 1 {
                    return Err(Vp9Error::BufferTooShort);
                }
                pid = (pid << 8) | buf[offset] as u16;
                offset += 1;
            }
            picture_id = Some(pid);
        }
        Ok((
            Self {
                i_bit,
                p_bit,
                l_bit,
                f_bit,
                b_bit,
                e_bit,
                v_bit,
                z_bit,
                picture_id,
            },
            offset,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vp9_payload_descriptor_basic() {
        // I=1 P=0 L=0 F=0 B=1 E=0 V=0 Z=0, PictureID=13 (7-bit)
        let b0 = 0x80 /*I*/ | 0x08 /*B*/;
        let pic = 0x0D; // M=0, id=13
        let buf = [b0, pic, 0xAA, 0xBB];
        let (desc, off) = Vp9PayloadDesc::parse(&buf).unwrap();
        assert!(desc.i_bit);
        assert!(desc.b_bit);
        assert!(!desc.e_bit);
        assert_eq!(desc.picture_id, Some(13));
        assert_eq!(off, 2);
    }
}
