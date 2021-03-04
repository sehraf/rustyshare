use std::{sync::mpsc, thread, time::Duration};

// use openssl::ssl::SslConnector;

use crate::{
    error::RsError,
    model::{PeerCommand, PeerStatus},
    parser::{headers::Header, Packet, Parser},
    retroshare_compat::LocationId,
    serial_stuff,
    services::Services,
    transport::Transport,
};

// pub struct ConnectionBuilder {}

// impl ConnectionBuilder {
//     pub fn bootstrap(
//         loc: &LocationId,
//         connector: &Arc<SslConnector>,
//         ips: Vec<ConnectionType>,
//         inner_rx: mpsc::Receiver<PeerCommand>,
//         outer_tx: mpsc::Sender<PeerCommand>,
//     ) {
//         if let Ok(transport) = Self::try_connect(&connector, ips) {
//             outer_tx
//                 .send(PeerCommand::PeerUpdate(PeerStatus::Online(loc.clone())))
//                 .unwrap();

//             // start regular peer communication
//             PeerConnection::new(loc.clone(), transport, inner_rx, outer_tx).run();
//         }
//     }

//     pub fn try_connect(
//         connector: &Arc<SslConnector>,
//         mut ips: Vec<ConnectionType>,
//     ) -> Result<Transport, RsError> {
//         // let mut ip_iter = ips.iter_mut();

//         // while let Some(t) = ip_iter.next() {
//         //     match t {
//         //         ConnectionType::Tcp(addr) => {
//         //             if let Ok(tcp) = TcpTransport::try_connect(&addr) {
//         //                 let ssl = RsSsl::connect_tls(tcp.try_clone().unwrap(), &connector).unwrap();
//         //                 return Ok(Transport {
//         //                     target: t.clone(),
//         //                     // socket: Box::new(tcp),
//         //                     stream: ssl,
//         //                 });
//         //             }
//         //             continue;
//         //         }
//         //         _ => panic!("not supported"),
//         //     }
//         // }
//         Err(RsError::default())
//     }
// }

pub struct PeerConnection {
    location_id: LocationId,
    // connection: Box<dyn Read + Write>,
    transport: Transport,

    parser: Parser,
    services: Services,

    data_out: Vec<Packet>,

    inner_rx: mpsc::Receiver<PeerCommand>,
    outer_tx: mpsc::Sender<PeerCommand>,
}

impl PeerConnection {
    pub fn new(
        location_id: LocationId,
        // connection: Box<dyn Read + Write>,
        transport: Transport,
        // ssl: SslStream<TcpStream>,
        // services: Services,
        rx: mpsc::Receiver<PeerCommand>,
        tx: mpsc::Sender<PeerCommand>,
    ) -> PeerConnection {
        // let ssl = ssl.try_unwrap().unwrap();

        let services = Services::get_peer_services();

        PeerConnection {
            location_id,
            transport,
            parser: Parser::new(),
            services,
            data_out: vec![],
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
            // let mut slice = &buf[read..len - read];
            match self
                .transport
                .stream
                // .ssl_stream
                .ssl_read(&mut buf[read..len - read])
            {
                Ok(length) => {
                    // println!("got {:?} bytes: {:X?}", length, &buf);
                    read += length;
                }
                Err(why) => {
                    panic!("failed to read payload: {:?}", why);
                }
            }
        }
        buf
    }

    // pub fn read_packet(&mut self) -> Option<(Header, Vec<u8>)> {
    pub fn read_packet(&mut self) -> Result<(Header, Vec<u8>), RsError> {
        let mut header: [u8; 4 + 4] = [0; 8]; // type + size
        match self.transport.stream.ssl_read(&mut header) {
            Ok(0) => {
                println!("zero read")
            }
            Ok(length) => {
                assert_eq!(&length, &8);
                // println!("got header {} bytes {:02X?}", &length, &header);

                // parse header
                let raw = Header::Raw { data: header };
                let header = match raw.try_parse() {
                    Ok(h) => h,
                    Err(why) => {
                        println!("failed to parse header: {:?}", &why);
                        // self.ssl.read_to_end(_);
                        return Err(why);
                    }
                };
                // dbg!(&header);

                let payload_size = match header.get_payload_size() {
                    Ok(size) => size,
                    Err(why) => {
                        println!("failed to read payload_size: {:?}", why);
                        // self.ssl.read_to_end(_);
                        return Err(why);
                    }
                };
                // println!("reading {} bytes payload", payload_size);
                let buf = self.read_data(payload_size);
                assert_eq!(payload_size, buf.len());
                return Ok((header, buf));
            }
            Err(why) if openssl::ssl::ErrorCode::WANT_READ == why.code() => {}
            Err(why) if openssl::ssl::ErrorCode::from_raw(6) == why.code() => {
                // "the SSL session has been shut down"
                return Err(why.into());
            }
            Err(why) => println!("failed to read header: {}", why),
        }
        Err(RsError::Generic)
    }

    fn write(&mut self, data: &Vec<u8>) {
        // println!("writing: {:02X?}", &data);
        match self.transport.stream.ssl_write(data) {
            Ok(_) => {}
            Err(why) => println!("failed to write: {:?}", why),
        }
    }

    fn boot_up(&mut self) {
        std::thread::sleep(Duration::from_secs(1));
        self.write(&serial_stuff::gen_slice_probe());
        self.write(&serial_stuff::gen_service_info(
            self.services.get_services(),
        ));
    }

    fn run_loop(&mut self) {
        println!("dispatching");
        self.boot_up();

        let mut sick = false;

        loop {
            // self.debug_print();
            thread::sleep(Duration::from_millis(100));

            // handle com in
            match self.inner_rx.try_recv() {
                Ok(msg) => {
                    println!("got {:?}", msg);
                }
                Err(why) => match why {
                    mpsc::TryRecvError::Empty => {}
                    mpsc::TryRecvError::Disconnected => {
                        println!("Channel broken :(");
                        break;
                    }
                },
            }

            // receive packets
            while let Ok(packet) = match self.read_packet() {
                Ok(p) => Ok(p),
                Err(RsError::Generic) => Err(()),
                Err(RsError::Ssl(_)) => {
                    sick = true;
                    Err(())
                }
                _ => Err(()),
            } {
                if let Some(item) = self.parser.parse_packet(packet.0, packet.1) {
                    if let Some(answer) = self.services.handle_packet(item) {
                        self.write(&answer);
                    }
                }
            }

            // handle services
            if let Some(items) = self.services.tick_all() {
                for item in items {
                    self.write(&item);
                }
            }

            // handle com out
            for packet in &self.data_out {
                self.outer_tx
                    .send(PeerCommand::Send(packet.clone()))
                    .unwrap();
            }
            self.data_out.clear();

            // still alive?
            if sick {
                break;
            }
        }

        // good bye
        self.outer_tx
            .send(PeerCommand::PeerUpdate(PeerStatus::Offline(
                self.location_id.clone(),
            )))
            .unwrap();
    }

    pub fn run(&mut self) {
        self.run_loop();
    }
}
