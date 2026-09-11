//! The adapter's side of one session: what a test or the loopback puts at
//! the far end so a scanner can be driven without a drive in the room.
//!
//! Not a device. One adapter serves one scanner and holds assemblies as
//! byte vectors by instance: it registers the session, answers a get from
//! an assembly and a set into one, and refuses what is not there with the
//! general status a device would use.

use std::collections::HashMap;
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use transport::error::{Result, classify};
use transport::socket;

use crate::cip::{
    self, ASSEMBLY, DATA_ATTRIBUTE, GET_ATTRIBUTE_SINGLE, Reply, Request, SET_ATTRIBUTE_SINGLE,
};
use crate::encapsulation::{self, Packet, REGISTER_SESSION, SEND_RR_DATA, UNREGISTER_SESSION};

/// The adapter's side of one session: assemblies as byte vectors by
/// instance, served until the scanner unregisters or closes.
pub struct Adapter {
    stream: TcpStream,
    peer: SocketAddr,
    session: u32,
    assemblies: HashMap<u8, Vec<u8>>,
}

impl Adapter {
    /// Accept one scanner on `listener`.
    ///
    /// # Errors
    /// Where the connection could not be accepted.
    pub fn accept(listener: &TcpListener, timeout: Option<Duration>) -> Result<Self> {
        let (stream, peer) = socket::accept_tcp(listener, timeout)?;
        Ok(Self {
            stream,
            peer,
            session: 0,
            assemblies: HashMap::new(),
        })
    }

    /// Hold `bytes` as assembly `instance`.
    #[must_use]
    pub fn with_assembly(mut self, instance: u8, bytes: impl Into<Vec<u8>>) -> Self {
        self.assemblies.insert(instance, bytes.into());
        self
    }

    /// The data of assembly `instance`, as it is now.
    #[must_use]
    pub fn assembly(&self, instance: u8) -> Option<&[u8]> {
        self.assemblies.get(&instance).map(Vec::as_slice)
    }

    /// Where the scanner's messages come from: `enip://peer/assembly/<n>`.
    #[must_use]
    pub fn origin(&self, instance: u8) -> String {
        format!("enip://{}/assembly/{instance}", self.peer)
    }

    /// Serve the scanner until it unregisters or closes.
    ///
    /// # Errors
    /// Where the connection broke or the scanner did not speak `EtherNet/IP`.
    pub fn serve(&mut self) -> Result<()> {
        while let Some(packet) = Packet::read(&mut self.stream)? {
            let answer = match packet.command {
                REGISTER_SESSION => {
                    self.session = 0x0001_0001;
                    Packet {
                        session: self.session,
                        ..packet
                    }
                }
                UNREGISTER_SESSION => return Ok(()),
                SEND_RR_DATA if packet.session == self.session && self.session != 0 => {
                    let request = Request::decode(&encapsulation::rr_cip(&packet.data)?)?;
                    let reply = self.explicit(&request);
                    Packet {
                        data: encapsulation::rr_data(&reply.encode())?,
                        ..packet
                    }
                }
                _ => Packet {
                    status: 0x0001,
                    data: Vec::new(),
                    ..packet
                },
            };
            self.stream
                .write_all(&answer.encode()?)
                .map_err(|e| classify("writing to the scanner", &e))?;
        }
        Ok(())
    }

    fn explicit(&mut self, request: &Request) -> Reply {
        let instance = u8::try_from(request.path.instance).unwrap_or(u8::MAX);
        if request.path.class != ASSEMBLY || request.path.attribute != DATA_ATTRIBUTE {
            return Reply::to(request.service, cip::PATH_DESTINATION_UNKNOWN, Vec::new());
        }
        match (request.service, self.assemblies.get_mut(&instance)) {
            (_, None) => Reply::to(request.service, cip::PATH_DESTINATION_UNKNOWN, Vec::new()),
            (GET_ATTRIBUTE_SINGLE, Some(bytes)) => {
                Reply::to(request.service, cip::SUCCESS, bytes.clone())
            }
            (SET_ATTRIBUTE_SINGLE, Some(bytes)) => {
                bytes.clone_from(&request.data);
                Reply::to(request.service, cip::SUCCESS, Vec::new())
            }
            _ => Reply::to(request.service, cip::SERVICE_NOT_SUPPORTED, Vec::new()),
        }
    }
}
