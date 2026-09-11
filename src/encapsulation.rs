//! The `EtherNet/IP` encapsulation, ODVA volume 2 chapter 2: a twenty-four
//! byte header on every packet — command, length, session handle, status,
//! sender context, options — and the common packet format that carries CIP
//! in a `SendRRData`.
//!
//! Three commands are what an explicit message needs: `RegisterSession`
//! opens a session and hands back the handle every later packet carries,
//! `SendRRData` carries one request and one reply as an address item and a
//! data item, and `UnregisterSession` closes.

use std::io::Read;

use transport::error::{Result, classify, protocol_error};

/// The TCP port an adapter listens on.
pub const PORT: u16 = 44818;

pub const REGISTER_SESSION: u16 = 0x0065;
pub const UNREGISTER_SESSION: u16 = 0x0066;
pub const SEND_RR_DATA: u16 = 0x006f;

/// The header on every packet.
pub const HEADER: usize = 24;

/// What a `SendRRData` carries before its CIP: interface handle, timeout,
/// item count, the null address item, the unconnected data item's header.
pub const RR_OVERHEAD: usize = 4 + 2 + 2 + 4 + 4;

const NULL_ADDRESS: u16 = 0x0000;
const UNCONNECTED_DATA: u16 = 0x00b2;

/// One encapsulation packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub command: u16,
    pub session: u32,
    pub status: u32,
    pub context: [u8; 8],
    pub data: Vec<u8>,
}

impl Packet {
    /// `command` under `session` carrying `data`, status 0, no context.
    #[must_use]
    pub fn new(command: u16, session: u32, data: Vec<u8>) -> Self {
        Self {
            command,
            session,
            status: 0,
            context: [0; 8],
            data,
        }
    }

    /// The packet as bytes on the wire.
    ///
    /// # Errors
    /// Data over what the sixteen-bit length names.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let length = u16::try_from(self.data.len())
            .map_err(|_| protocol_error("over what one encapsulation packet carries"))?;
        let mut out = Vec::with_capacity(HEADER + self.data.len());
        out.extend_from_slice(&self.command.to_le_bytes());
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(&self.session.to_le_bytes());
        out.extend_from_slice(&self.status.to_le_bytes());
        out.extend_from_slice(&self.context);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    /// The next packet on `reader`, or `None` when the peer closed between
    /// packets.
    ///
    /// # Errors
    /// A connection that closes mid-packet, or options that are not zero.
    pub fn read(reader: &mut impl Read) -> Result<Option<Self>> {
        let mut head = [0u8; HEADER];
        let first = reader
            .read(&mut head[..1])
            .map_err(|e| classify("reading the encapsulation header", &e))?;
        if first == 0 {
            return Ok(None);
        }
        reader
            .read_exact(&mut head[1..])
            .map_err(|e| classify("reading the encapsulation header", &e))?;
        let length = usize::from(u16::from_le_bytes([head[2], head[3]]));
        if head[20..24] != [0; 4] {
            return Err(protocol_error("encapsulation options that are not zero"));
        }
        let mut data = vec![0u8; length];
        reader
            .read_exact(&mut data)
            .map_err(|e| classify("reading the encapsulation data", &e))?;
        let mut context = [0u8; 8];
        context.copy_from_slice(&head[12..20]);
        Ok(Some(Self {
            command: u16::from_le_bytes([head[0], head[1]]),
            session: u32::from_le_bytes([head[4], head[5], head[6], head[7]]),
            status: u32::from_le_bytes([head[8], head[9], head[10], head[11]]),
            context,
            data,
        }))
    }
}

/// What a `RegisterSession` carries: protocol version 1, no options.
#[must_use]
pub fn register_data() -> Vec<u8> {
    vec![1, 0, 0, 0]
}

/// `cip` as the data of a `SendRRData`: interface handle 0, no timeout, a
/// null address item and an unconnected data item.
///
/// # Errors
/// CIP longer than an item's sixteen-bit length names.
pub fn rr_data(cip: &[u8]) -> Result<Vec<u8>> {
    let length =
        u16::try_from(cip.len()).map_err(|_| protocol_error("over what one data item carries"))?;
    let mut out = Vec::with_capacity(RR_OVERHEAD + cip.len());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&NULL_ADDRESS.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&UNCONNECTED_DATA.to_le_bytes());
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(cip);
    Ok(out)
}

/// The CIP a `SendRRData`'s data carries.
///
/// # Errors
/// Fewer than two items, an address item that is not null, a data item
/// that is not unconnected, or a length past the end.
pub fn rr_cip(data: &[u8]) -> Result<Vec<u8>> {
    let head = data
        .get(..RR_OVERHEAD)
        .ok_or_else(|| protocol_error("SendRRData shorter than its items"))?;
    let count = u16::from_le_bytes([head[6], head[7]]);
    if count < 2 {
        return Err(protocol_error("fewer than two items in SendRRData"));
    }
    if u16::from_le_bytes([head[8], head[9]]) != NULL_ADDRESS {
        return Err(protocol_error("an address item that is not null"));
    }
    if u16::from_le_bytes([head[12], head[13]]) != UNCONNECTED_DATA {
        return Err(protocol_error("a data item that is not unconnected data"));
    }
    let length = usize::from(u16::from_le_bytes([head[14], head[15]]));
    data.get(RR_OVERHEAD..RR_OVERHEAD + length)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| protocol_error("a data item length past the end"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_packet_round_trips_with_its_header() {
        let packet = Packet::new(REGISTER_SESSION, 0, register_data());
        let wire = packet.encode().expect("encode");
        assert_eq!(wire.len(), 28);
        assert_eq!(&wire[..4], &[0x65, 0x00, 0x04, 0x00]);
        assert_eq!(
            Packet::read(&mut wire.as_slice()).expect("read"),
            Some(packet)
        );
        assert!(Packet::read(&mut &[][..]).expect("closed").is_none());
        assert!(Packet::read(&mut &wire[..10]).is_err(), "closed mid-header");
        let mut options = wire.clone();
        options[20] = 1;
        assert!(Packet::read(&mut options.as_slice()).is_err(), "options");
        assert!(
            Packet::new(SEND_RR_DATA, 1, vec![0; 65_536])
                .encode()
                .is_err()
        );
    }

    #[test]
    fn send_rr_data_wraps_cip_in_two_items_and_unwraps_it() {
        let data = rr_data(&[0x0e, 3, 0x20, 4, 0x24, 100, 0x30, 3]).expect("rr");
        assert_eq!(data.len(), RR_OVERHEAD + 8);
        assert_eq!(&data[6..8], &[2, 0], "two items");
        assert_eq!(&data[12..16], &[0xb2, 0x00, 8, 0]);
        assert_eq!(
            rr_cip(&data).expect("cip"),
            [0x0e, 3, 0x20, 4, 0x24, 100, 0x30, 3]
        );
        assert!(rr_cip(&data[..10]).is_err(), "short");
        let mut one = data.clone();
        one[6] = 1;
        assert!(rr_cip(&one).is_err(), "one item");
        let mut connected = data.clone();
        connected[8] = 0xa1;
        assert!(rr_cip(&connected).is_err(), "a connected address");
        let mut wrong = data.clone();
        wrong[12] = 0xb1;
        assert!(rr_cip(&wrong).is_err(), "connected data");
        let mut past = data;
        past[14] = 9;
        assert!(rr_cip(&past).is_err(), "past the end");
    }
}
