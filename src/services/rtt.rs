use async_trait::async_trait;
use log::debug;
use retroshare_compat::{
    serde::{from_retroshare_wire_result, to_retroshare_wire_result},
    services::rtt::{RttPingItem, RttPongItem},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{
    handle_packet,
    low_level_parsing::{headers::ServiceHeader, Packet},
    services::{HandlePacketResult, Service},
    utils::{simple_stats::StatsCollection, Timer, Timers},
};

use super::ServiceType;

const RTT_TIMER: (&str, Duration) = ("rtt", Duration::from_secs(5));

const RTT_SUB_TYPE_PING: u8 = 0x01;
const RTT_SUB_TYPE_PONG: u8 = 0x02;

pub struct Rtt {
    next_seq_num: u32,
}

impl Rtt {
    pub fn new(timers: &mut Timers) -> Rtt {
        timers.insert(RTT_TIMER.0.into(), Timer::new(RTT_TIMER.1));

        Rtt { next_seq_num: 1 }
    }

    pub fn handle_incoming(
        &self,
        header: &ServiceHeader,
        mut packet: Packet,
    ) -> HandlePacketResult {
        match header.sub_type {
            RTT_SUB_TYPE_PING => {
                let ping: RttPingItem = from_retroshare_wire_result(&mut packet.payload)
                    .expect("failed to deserialize");

                let item = Rtt::gen_pong(ping);
                return handle_packet!(item);
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
            sub_type => log::error!("[RTT] recevied unknown sub typ {sub_type}"),
        }
        handle_packet!()
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

        let payload = to_retroshare_wire_result(&ping).expect("failed to serialize");
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

        let payload = to_retroshare_wire_result(&pong).expect("failed to serialize");
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

    async fn handle_packet(&self, packet: Packet) -> HandlePacketResult {
        debug!("handle_packet");

        self.handle_incoming(&packet.header.into(), packet)
    }

    async fn tick(
        &mut self,
        _stats: &mut StatsCollection,
        timers: &mut Timers,
    ) -> Option<Vec<Packet>> {
        let mut items: Vec<Packet> = vec![];
        // if self.last_ping.elapsed().unwrap_or_default().as_secs() >= 5 {
        if timers.get_mut(RTT_TIMER.0.into()).unwrap().expired() {
            let item = Rtt::gen_ping(self.next_seq_num.clone());
            items.push(item);

            self.next_seq_num = self.next_seq_num.wrapping_add(1);
            // self.last_ping = SystemTime::now();
        }
        if items.len() > 0 {
            return Some(items);
        } else {
            return None;
        }
    }

    fn get_service_info(&self) -> (String, u16, u16, u16, u16) {
        (String::from("rtt"), 1, 0, 1, 0)
    }
}
