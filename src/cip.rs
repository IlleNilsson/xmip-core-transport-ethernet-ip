//! The common industrial protocol's explicit message, ODVA volume 1
//! appendix C: a service, a path to a class, an instance and an attribute,
//! and the data; and the reply with its general status.
//!
//! Two services move one attribute: `Get_Attribute_Single` reads it and
//! `Set_Attribute_Single` writes it. The assembly object, class 4, is where
//! a device presents its IO as bytes; its data attribute, 3, is the Stream.

use transport::error::{Result, protocol_error};

pub const GET_ATTRIBUTE_SINGLE: u8 = 0x0e;
pub const SET_ATTRIBUTE_SINGLE: u8 = 0x10;

/// The assembly object's class, and its data attribute.
pub const ASSEMBLY: u16 = 0x04;
pub const DATA_ATTRIBUTE: u16 = 3;

/// The general statuses an adapter answers with.
pub const SUCCESS: u8 = 0x00;
pub const PATH_DESTINATION_UNKNOWN: u8 = 0x05;
pub const SERVICE_NOT_SUPPORTED: u8 = 0x08;
pub const ATTRIBUTE_NOT_SETTABLE: u8 = 0x0e;

/// The service byte, the path size byte, and a path of three eight-bit
/// logical segments.
pub const REQUEST_OVERHEAD: usize = 2 + 6;

/// A logical path: class, instance, attribute.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Path {
    pub class: u16,
    pub instance: u16,
    pub attribute: u16,
}

impl Path {
    /// The path as logical segments, padded to whole words.
    #[must_use]
    pub fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12);
        for (kind, value) in [
            (0x20, self.class),
            (0x24, self.instance),
            (0x30, self.attribute),
        ] {
            if let Ok(byte) = u8::try_from(value) {
                out.extend_from_slice(&[kind, byte]);
            } else {
                out.extend_from_slice(&[kind | 0x01, 0]);
                out.extend_from_slice(&value.to_le_bytes());
            }
        }
        out
    }

    /// The path `bytes` carry.
    ///
    /// # Errors
    /// A segment that is not a logical class, instance or attribute, or one
    /// cut short.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut path = Self {
            class: 0,
            instance: 0,
            attribute: 0,
        };
        let mut at = 0;
        while at < bytes.len() {
            let kind = bytes[at];
            let (value, taken) = if kind & 0x01 == 0 {
                let byte = *bytes
                    .get(at + 1)
                    .ok_or_else(|| protocol_error("a segment cut short"))?;
                (u16::from(byte), 2)
            } else {
                let word = bytes
                    .get(at + 2..at + 4)
                    .ok_or_else(|| protocol_error("a segment cut short"))?;
                (u16::from_le_bytes([word[0], word[1]]), 4)
            };
            match kind & 0xfe {
                0x20 => path.class = value,
                0x24 => path.instance = value,
                0x30 => path.attribute = value,
                other => {
                    return Err(protocol_error(format!(
                        "segment {other:#04x} is not a logical class, instance or attribute"
                    )));
                }
            }
            at += taken;
        }
        Ok(path)
    }
}

/// One explicit request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub service: u8,
    pub path: Path,
    pub data: Vec<u8>,
}

impl Request {
    /// The request as bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let path = self.path.encode();
        let mut out = Vec::with_capacity(2 + path.len() + self.data.len());
        out.push(self.service);
        out.push(u8::try_from(path.len() / 2).unwrap_or(u8::MAX));
        out.extend_from_slice(&path);
        out.extend_from_slice(&self.data);
        out
    }

    /// The request `bytes` carry.
    ///
    /// # Errors
    /// Shorter than a service and a path size, a reply where a request was
    /// due, or a path past the end.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let (&service, rest) = bytes
            .split_first()
            .ok_or_else(|| protocol_error("an empty CIP request"))?;
        if service & 0x80 != 0 {
            return Err(protocol_error("a reply where a request was due"));
        }
        let (&words, rest) = rest
            .split_first()
            .ok_or_else(|| protocol_error("a request without its path size"))?;
        let length = usize::from(words) * 2;
        let path = rest
            .get(..length)
            .ok_or_else(|| protocol_error("a path past the end"))?;
        Ok(Self {
            service,
            path: Path::decode(path)?,
            data: rest[length..].to_vec(),
        })
    }
}

/// One reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    /// The request's service with the reply bit set.
    pub service: u8,
    pub status: u8,
    pub data: Vec<u8>,
}

impl Reply {
    /// The reply to `service` with `status` carrying `data`.
    #[must_use]
    pub fn to(service: u8, status: u8, data: Vec<u8>) -> Self {
        Self {
            service: service | 0x80,
            status,
            data,
        }
    }

    /// The reply as bytes: service, reserved, status, no additional status.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.data.len());
        out.extend_from_slice(&[self.service, 0, self.status, 0]);
        out.extend_from_slice(&self.data);
        out
    }

    /// The reply `bytes` carry.
    ///
    /// # Errors
    /// Shorter than its four bytes, a request where a reply was due, or
    /// additional status past the end.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 4 {
            return Err(protocol_error("a CIP reply shorter than its header"));
        }
        if bytes[0] & 0x80 == 0 {
            return Err(protocol_error("a request where a reply was due"));
        }
        let additional = usize::from(bytes[3]) * 2;
        let data = bytes
            .get(4 + additional..)
            .ok_or_else(|| protocol_error("additional status past the end"))?;
        Ok(Self {
            service: bytes[0],
            status: bytes[2],
            data: data.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_set_of_an_assembly_attribute_round_trips() {
        let request = Request {
            service: SET_ATTRIBUTE_SINGLE,
            path: Path {
                class: ASSEMBLY,
                instance: 100,
                attribute: DATA_ATTRIBUTE,
            },
            data: vec![1, 2, 3],
        };
        let wire = request.encode();
        assert_eq!(wire, [0x10, 3, 0x20, 4, 0x24, 100, 0x30, 3, 1, 2, 3]);
        assert_eq!(wire.len(), REQUEST_OVERHEAD + 3);
        assert_eq!(Request::decode(&wire).expect("decode"), request);
        let long_path = Path {
            class: 0x1234,
            instance: 300,
            attribute: 1,
        };
        assert_eq!(
            long_path.encode(),
            [0x21, 0, 0x34, 0x12, 0x25, 0, 0x2c, 0x01, 0x30, 1]
        );
        assert_eq!(Path::decode(&long_path.encode()).expect("long"), long_path);
    }

    #[test]
    fn a_reply_carries_its_status_and_skips_additional_status() {
        let reply = Reply::to(GET_ATTRIBUTE_SINGLE, SUCCESS, vec![9, 9]);
        assert_eq!(reply.encode(), [0x8e, 0, 0, 0, 9, 9]);
        assert_eq!(Reply::decode(&reply.encode()).expect("decode"), reply);
        let extended = [0x90, 0, PATH_DESTINATION_UNKNOWN, 1, 0x34, 0x12, 7];
        let back = Reply::decode(&extended).expect("decode");
        assert_eq!(back.status, PATH_DESTINATION_UNKNOWN);
        assert_eq!(back.data, [7]);
    }

    #[test]
    fn what_is_not_cip_is_refused() {
        assert!(Request::decode(&[]).is_err(), "empty");
        assert!(Request::decode(&[0x8e, 0]).is_err(), "a reply");
        assert!(Request::decode(&[0x0e]).is_err(), "no path size");
        assert!(
            Request::decode(&[0x0e, 3, 0x20, 4]).is_err(),
            "path past the end"
        );
        assert!(
            Request::decode(&[0x0e, 1, 0x28, 4]).is_err(),
            "not a logical segment"
        );
        assert!(Path::decode(&[0x21, 0, 0x34]).is_err(), "cut short");
        assert!(Path::decode(&[0x20]).is_err(), "cut short");
        assert!(Reply::decode(&[0x8e, 0, 0]).is_err(), "short");
        assert!(Reply::decode(&[0x0e, 0, 0, 0]).is_err(), "a request");
        assert!(
            Reply::decode(&[0x8e, 0, 0, 4]).is_err(),
            "additional past the end"
        );
    }
}
