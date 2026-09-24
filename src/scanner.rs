//! The scanner's side of one session: register, get and set an assembly's
//! data attribute by explicit message, unregister. What a Location does on
//! every receive and every send.

use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;

use transport::ceiling;
use transport::error::{Result, classify, protocol_error};
use transport::socket;

use crate::CEILING;
use crate::cip::{
    self, ASSEMBLY, DATA_ATTRIBUTE, GET_ATTRIBUTE_SINGLE, Path, Reply, Request,
    SET_ATTRIBUTE_SINGLE,
};
use crate::encapsulation::{self, Packet, REGISTER_SESSION, SEND_RR_DATA, UNREGISTER_SESSION};

/// The scanner's side of one session.
pub struct Scanner {
    stream: TcpStream,
    session: u32,
}

impl Scanner {
    /// Connect to the adapter at `address` and register a session.
    ///
    /// # Errors
    /// Where the adapter could not be reached or did not register.
    pub fn connect(address: &str, timeout: Option<Duration>) -> Result<Self> {
        let stream = socket::connect_tcp(address, timeout)?;
        let mut scanner = Self { stream, session: 0 };
        let answer = scanner.exchange(&Packet::new(
            REGISTER_SESSION,
            0,
            encapsulation::register_data(),
        ))?;
        if answer.command != REGISTER_SESSION || answer.status != 0 || answer.session == 0 {
            return Err(protocol_error("the adapter did not register the session"));
        }
        scanner.session = answer.session;
        Ok(scanner)
    }

    /// The session handle the adapter gave.
    #[must_use]
    pub const fn session(&self) -> u32 {
        self.session
    }

    /// The data attribute of assembly `instance`.
    ///
    /// # Errors
    /// An adapter that has no such assembly or went away.
    pub fn get(&mut self, instance: u8) -> Result<Vec<u8>> {
        let reply = self.explicit(GET_ATTRIBUTE_SINGLE, instance, &[])?;
        Ok(reply.data)
    }

    /// Set the data attribute of assembly `instance` to `bytes`.
    ///
    /// # Errors
    /// Over the [`CEILING`], or an adapter that refused or went away.
    pub fn set(&mut self, instance: u8, bytes: &[u8]) -> Result<()> {
        ceiling::within(bytes.len(), CEILING, "one set carries")?;
        self.explicit(SET_ATTRIBUTE_SINGLE, instance, bytes)?;
        Ok(())
    }

    /// Unregister and close.
    ///
    /// # Errors
    /// Where the adapter had already gone.
    pub fn unregister(mut self) -> Result<()> {
        let packet = Packet::new(UNREGISTER_SESSION, self.session, Vec::new());
        self.stream
            .write_all(&packet.encode()?)
            .map_err(|e| classify("writing the unregister", &e))
    }

    fn explicit(&mut self, service: u8, instance: u8, data: &[u8]) -> Result<Reply> {
        let request = Request {
            service,
            path: Path {
                class: ASSEMBLY,
                instance: u16::from(instance),
                attribute: DATA_ATTRIBUTE,
            },
            data: data.to_vec(),
        };
        let data = encapsulation::rr_data(&request.encode())?;
        let answer = self.exchange(&Packet::new(SEND_RR_DATA, self.session, data))?;
        if answer.command != SEND_RR_DATA || answer.status != 0 {
            return Err(protocol_error("the adapter refused the SendRRData"));
        }
        let reply = Reply::decode(&encapsulation::rr_cip(&answer.data)?)?;
        if reply.service != service | 0x80 {
            return Err(protocol_error("a reply to another service"));
        }
        if reply.status != cip::SUCCESS {
            return Err(protocol_error(format!(
                "the adapter answered general status {:#04x}",
                reply.status
            )));
        }
        Ok(reply)
    }

    fn exchange(&mut self, packet: &Packet) -> Result<Packet> {
        self.stream
            .write_all(&packet.encode()?)
            .map_err(|e| classify("writing to the adapter", &e))?;
        Packet::read(&mut self.stream)?
            .ok_or_else(|| protocol_error("the adapter closed before answering"))
    }
}
