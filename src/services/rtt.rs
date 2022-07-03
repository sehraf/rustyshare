use async_trait::async_trait;
use log::{debug, trace, warn};
use retroshare_compat::{
    serde::{from_retroshare_wire_result, to_retroshare_wire},
    services::{
        rtt::{RttPingItem, RttPongItem},
        service_info::RsServiceInfo,
    },
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::{
    select,
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
    time::interval,
};

use crate::{
    low_level_parsing::{headers::ServiceHeader, Packet},
    model::intercom::Intercom,
    send_to_peer,
    services::Service,
};

use ::retroshare_compat::services::ServiceType;

#[allow(dead_code)]const RTT_TIMER: (&str, Duration) = ("rtt", Duration::from_secs(5));

const RTT_SUB_TYPE_PING: u8 = 0x01;
const RTT_SUB_TYPE_PONG: u8 = 0x02;

pub struct Rtt {
    peer_tx: UnboundedSender<Intercom>,
    // core_tx: UnboundedSender<Intercom>,
    rx: UnboundedReceiver<Intercom>,

    next_seq_num: u32,
}

impl Rtt {
    pub fn new(
        _core_tx: UnboundedSender<Intercom>,
        peer_tx: UnboundedSender<Intercom>,
        rx: UnboundedReceiver<Intercom>,
    ) -> Rtt {
        Rtt {
            // core_tx,
            peer_tx,
            rx,
            next_seq_num: 1,
        }
    }

    async fn tick(&mut self) {
        let item = Rtt::gen_ping(self.next_seq_num.clone());
        send_to_peer!(self, item);

        self.next_seq_num = self.next_seq_num.wrapping_add(1);
    }

    fn handle_incoming(&self, header: &ServiceHeader, mut packet: Packet) {
        match header.sub_type {
            RTT_SUB_TYPE_PING => {
                let ping: RttPingItem = from_retroshare_wire_result(&mut packet.payload)
                    .expect("failed to deserialize");

                let item = Rtt::gen_pong(ping);
                self.peer_tx
                    .send(Intercom::Send(item))
                    .expect("failed to send to peer");
            }
            RTT_SUB_TYPE_PONG => {
                let pong: RttPongItem = from_retroshare_wire_result(&mut packet.payload)
                    .expect("failed to deserialize");

                let now_ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards");
                let ping_ts = Rtt::u64_to_ts(pong.ping.ping_ts);
                let pong_ts = Rtt::u64_to_ts(pong.pong_ts);

                // calculate actual rtt
                let rtt = now_ts.as_millis() - ping_ts.as_millis();
                // calculate offset out of their time, assuming, that both (ping and pong) packets had an equal travel time
                let offset = pong_ts.as_millis() as i128 - (now_ts.as_millis() - rtt / 2) as i128;

                debug!("received rtt: {rtt}ms with a {offset}ms offset");
            }
            sub_type => log::error!("received unknown sub typ {sub_type}"),
        }
    }

    fn gen_ping(seq_no: u32) -> Packet {
        let ping = RttPingItem {
            seq_no,
            ping_ts: Rtt::ts_to_u64(
                &SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards"),
            ),
        };

        let payload = to_retroshare_wire(&ping);
        let header = ServiceHeader::new(ServiceType::Rtt, RTT_SUB_TYPE_PING, &payload);

        Packet::new_without_location(header.into(), payload)
    }

    fn gen_pong(ping: RttPingItem) -> Packet {
        let pong = RttPongItem {
            ping,
            pong_ts: Rtt::ts_to_u64(
                &SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("Time went backwards"),
            ),
        };

        let payload = to_retroshare_wire(&pong);
        let header = ServiceHeader::new(ServiceType::Rtt, RTT_SUB_TYPE_PONG, &payload);

        Packet::new_without_location(header.into(), payload)
    }

    fn ts_to_u64(ts: &Duration) -> u64 {
        let sec: u32 = ts.as_secs() as u32;
        let usec: u32 = ts.subsec_micros();
        let mut t = (sec as u64) << 32;
        t += usec as u64;
        t
    }

    fn u64_to_ts(val: u64) -> Duration {
        let sec = val >> 32;
        let usec = val as u32;
        Duration::new(sec, usec)
    }
}

#[async_trait]
impl Service for Rtt {
    fn get_id(&self) -> ServiceType {
        ServiceType::Rtt
    }

    fn get_service_info(&self) -> RsServiceInfo {
        RsServiceInfo::new(self.get_id().into(), "rtt")
    }

    fn run(mut self) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut tick_timer = interval(Duration::from_secs(5));

            loop {
                select! {
                    msg = self.rx.recv() => {
                        if let Some(msg) = msg {
                            trace!("handling msg {msg:?}");
                            match msg {
                                Intercom::Receive(packet) => self.handle_incoming(&packet.header.to_owned().into(), packet),
                                _ => warn!("unexpected message: {msg:?}"),
                            }
                        }
                    }
                    _ = tick_timer.tick() => {
                        self.tick().await;
                    }
                }
            }
        })
    }
}
