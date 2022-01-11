use std::{
    collections::HashMap,
    // io::{Read, Write},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use retroshare_compat::{basics::*, service_info::RsServiceInfo};

use crate::{
    error::RsError,
    model::{PeerCommand, PeerState, PeerUpdate},
    parser::{
        headers::{Header, HEADER_SIZE},
        Packet, Parser,
    },
    serial_stuff,
    services::{service_info, HandlePacketResult, Services},
    transport::RsPeerConnection,
    utils::simple_stats::StatsCollection,
};

pub struct PeerConnection<T>
where
    T: RsPeerConnection,
{
    location_id: PeerId,
    transport: Box<T>,

    parser: Parser,
    services: Services,

    inner_rx: mpsc::Receiver<PeerCommand>,
    outer_tx: mpsc::Sender<PeerCommand>,
}

impl<T> PeerConnection<T>
where
    T: RsPeerConnection,
{
    pub fn new(
        location_id: PeerId,
        transport: Box<T>,

        rx: mpsc::Receiver<PeerCommand>,
        tx: mpsc::Sender<PeerCommand>,
    ) -> PeerConnection<T> {
        let services = Services::get_peer_services();

        PeerConnection {
            location_id,
            transport,
            parser: Parser::new(),
            services,

            inner_rx: rx,
            outer_tx: tx,
        }
    }

    fn read_data(&mut self, len: usize) -> Vec<u8> {
        // println!("reading {} bytes", len);
        let mut buf: Vec<u8> = vec![];
        buf.resize(len, 0);

        let mut read = 0;
        while read < len {
            match self.transport.read(&mut buf[read..]) {
                Ok(length) => {
                    // println!("got {:?} bytes: {:X?}", length, &buf);
                    read += length;
                }
                Err(why) => {
                    panic!("[peer] failed to read payload: {:?}", why);
                }
            }
        }
        buf
    }

    pub fn read_packet(&mut self) -> Result<(Header, Vec<u8>), RsError> {
        let mut header: [u8; HEADER_SIZE] = [0; HEADER_SIZE]; // type + size
        match self.transport.read(&mut header) {
            Ok(0) => {
                println!("[peer] zero read");
            }
            Ok(length) => {
                assert_eq!(&length, &8);
                // println!("got header {} bytes {:02X?}", &length, &header);

                // match self.transport.stream.read_exact(&mut header) {
                // Ok(()) => {
                // println!("got header {:02X?}", &header);

                // parse header
                let header = match Header::try_parse(header) {
                    Ok(h) => h,
                    Err(why) => {
                        println!("[peer] failed to parse header: {:?}", &why);
                        return Err(why);
                    }
                };

                let payload_size = header.get_payload_size();

                // println!("reading {} bytes payload", payload_size);

                let buf = self.read_data(payload_size);
                assert_eq!(payload_size, buf.len());

                // let mut buf: Vec<u8> = vec![];
                // buf.resize(payload_size, 0);
                // self.transport.stream.read_exact(buf.as_mut_slice())?;

                return Ok((header, buf));
            }
            // Err(why) if openssl::ssl::ErrorCode::WANT_READ == why.code() => {}
            // Err(why) if openssl::ssl::ErrorCode::from_raw(6) == why.code() => {
            //     // "the SSL session has been shut down"
            //     return Err(why.into());
            // }
            // Err(why)
            //     if openssl::ssl::ErrorCode::SYSCALL == why.code() && why.io_error().is_none() =>
            // {
            //     // EOF error, socket is probaly dead
            //     return Err(why.into());
            // }
            Err(why) if why.kind() == std::io::ErrorKind::ConnectionReset => {
                return Err(why.into());
            }
            Err(why) if why.kind() == std::io::ErrorKind::WouldBlock => {}

            // TODO better handle errors
            Err(why) => println!("[peer] failed to read header: {:?}", why),
        }
        Err(RsError::Generic)
    }

    fn write(&mut self, data: &Vec<u8>) {
        // println!("writing: {:02X?}", &data);
        match self.transport.write(data) {
            // match self.transport.stream.write_all(data) {
            Ok(_) => {}
            Err(why) => println!("[peer] failed to write: {:?}", why),
        }
    }

    fn send_packet(&mut self, packer: Packet) {
        for packet in self.parser.handle_outgoign_packet(packer) {
            self.write(&packet);
        }
    }

    fn boot_up(&mut self) {
        // give the other side some time to initialize
        std::thread::sleep(Duration::from_secs(1));

        // write it directly!
        self.write(&serial_stuff::gen_slice_probe());

        // now hanldle services
        let mut services: Vec<RsServiceInfo> =
            self.services.get_services().map(|s| s.into()).collect();

        // first message we expect are the cores services!
        loop {
            match self.inner_rx.try_recv() {
                Ok(PeerCommand::ServiceInfoUpdate(mut list)) => {
                    services.append(&mut list);
                    break;
                }
                Ok(m) => {
                    println!("[peer] received unexpected message: {:?}", m);
                }
                Err(mpsc::TryRecvError::Empty) => {
                    std::thread::sleep(Duration::from_millis(500));
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    panic!("failed to receive services from core!");
                }
            }
        }

        // send through parser
        self.send_packet(service_info::gen_service_info(&services));
    }

    fn run_loop(&mut self) {
        println!("[peer] dispatching");
        let mut sick = false;

        self.boot_up();

        // sleep time
        let mut now: Instant;
        const TARGET_INTERVAL: Duration = Duration::from_millis(25);

        loop {
            now = Instant::now();

            // handle communication (incoming)
            while let Ok(msg) = match self.inner_rx.try_recv() {
                // received a command
                Ok(msg) => Ok(msg),
                // nothing to read
                Err(mpsc::TryRecvError::Empty) => Err(()),
                // error case
                Err(mpsc::TryRecvError::Disconnected) => {
                    println!("[peer] Channel broken :(");
                    sick = true;
                    Err(())
                }
            } {
                match msg {
                    PeerCommand::Send(packet) => self.send_packet(packet),
                    msg => panic!("not implemented, received {:?}", msg),
                }
            }

            // receive packets
            while let Ok(packet) = match self.read_packet() {
                // received a packet
                Ok(p) => Ok(p),
                // generic error signals no packet available to read
                Err(RsError::Generic) => Err(()),
                // ssl errors are bad
                Err(RsError::Ssl(why)) => {
                    println!("[peer] got a ssl error: {}", why);
                    sick = true;
                    Err(())
                }
                // something else
                Err(why) => {
                    println!("[peer] unable to read packet: {:?}", why);
                    Err(())
                }
            } {
                // handle received packets
                if let Some(packet) =
                    self.parser
                        .handle_incoming_packet(packet.0, packet.1, &self.location_id)
                {
                    // try to handle local service first
                    // when no local service is able to handle the packet, send it to the core
                    match self.services.handle_packet(packet) {
                        // packet was locally handled and an answer was generated
                        HandlePacketResult::Handled(Some(answer)) => self.send_packet(answer),
                        // packet was locally handled and no answer was generated
                        HandlePacketResult::Handled(None) => {}
                        // packet was not locally handled as no fitting service was found
                        HandlePacketResult::NotHandled(packet) => {
                            // send packet to core for central processing
                            self.outer_tx.send(PeerCommand::Receive(packet)).unwrap()
                        }
                        // something else went wrong
                        HandlePacketResult::Error(why) => {
                            println!("[peer] failed to handle packet: {:?}", why)
                        }
                    }
                }
            }

            let mut stats_dummy: StatsCollection = (Instant::now(), HashMap::new());

            // handle service ticks
            if let Some(items) = self.services.tick_all(&mut stats_dummy) {
                for mut item in items {
                    // local services only send packets to the connected peer
                    if !item.has_location() {
                        item.peer_id = self.location_id;
                    }
                    self.send_packet(item);
                }
            }

            // still alive?
            if sick {
                println!("[peer] died of sickness {}", self.location_id);
                break;
            }

            // timing stuff
            // loop should run every TARGET_INTERVAL
            let loop_duration = Instant::now() - now;
            if loop_duration >= TARGET_INTERVAL {
                continue;
            }
            let sleep_duration = TARGET_INTERVAL - loop_duration;
            // println!("[peer] main loop execution took {}us sleeping for {}us", &loop_duration.as_millis(), &sleep_duration.as_millis());
            thread::sleep(sleep_duration);
        }

        // good bye
        self.outer_tx
            .send(PeerCommand::PeerUpdate(PeerUpdate::Status(
                PeerState::NotConnected(self.location_id.clone()),
            )))
            .expect("failed to communicate with core");
    }

    pub fn run(&mut self) {
        // notify core about a successfull connection
        match self.transport.target() {
            super::ConnectionType::Tcp(ip) | super::ConnectionType::Udp(ip) => {
                self.outer_tx
                    .send(PeerCommand::PeerUpdate(PeerUpdate::Status(
                        PeerState::Connected(self.location_id, ip),
                    )))
                    .expect("failed to communicate with core");
                self.run_loop();
            },
            #[allow(unreachable_patterns)]
            _ => unimplemented!("unable to get TCP connection infos"),
        }
    }
}
