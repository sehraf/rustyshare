use std::{
    net::{SocketAddr, TcpListener},
    sync::mpsc,
};

use crate::{
    error::RsError,
    model::{PeerCommand, PeerThreadCommand},
};

pub struct Listener {
    // addr: SocketAddr,
}

impl Listener {
    pub fn new(
        listen_addr: SocketAddr,
        outer_tx: mpsc::Sender<PeerCommand>,
        inner_rx: mpsc::Receiver<PeerCommand>,
    ) -> Result<std::thread::JoinHandle<()>, RsError> {
        println!("binding to {}", &listen_addr);
        let listener = TcpListener::bind(listen_addr)?;

        let handler = std::thread::spawn(move || {
            for con in listener.incoming() {
                match con {
                    Ok(stream) => outer_tx
                        .send(PeerCommand::Thread(PeerThreadCommand::Incoming(
                            stream.try_clone().unwrap(),
                        )))
                        .unwrap(),
                    Err(ref why) if why.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
                    Err(ref why) => println!("got error: {}", why),
                }
            }

            if let Ok(cmd) = inner_rx.try_recv() {
                match cmd {
                    PeerCommand::Thread(PeerThreadCommand::Stop) => return,
                    _ => {}
                }
            }
        });

        // Err(RsError::Generic)
        Ok(handler)
    }
}
