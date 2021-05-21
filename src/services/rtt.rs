use retroshare_compat::{read_u32, read_u64};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{
    parser::{
        headers::{Header, ServiceHeader},
        Packet,
    },
    serial_stuff,
    services::{HandlePacketResult, Service},
    utils::simple_stats::StatsCollection,
};

const RTT_SERVICE: u16 = 0x1011;
const RTT_SUB_TYPE_PING: u8 = 0x01;
const RTT_SUB_TYPE_PONG: u8 = 0x02;

pub struct Rtt {
    last_ping: SystemTime,
    next_seq_num: u32,
}

impl Rtt {
    pub fn new() -> Rtt {
        Rtt {
            last_ping: SystemTime::now(),
            next_seq_num: 1,
        }
    }

    pub fn handle_incoming(
        &self,
        header: &ServiceHeader,
        mut packet: Packet,
    ) -> HandlePacketResult {
        match header.sub_type {
            0x01 => {
                let seq_num = read_u32(&mut packet.payload); // mSeqNo
                let ping_64 = read_u64(&mut packet.payload); // mPingTS

                let item = Rtt::gen_pong(seq_num, ping_64);
                return HandlePacketResult::Handled(Some(item));
            }
            0x02 => {
                let _seq_num = read_u32(&mut packet.payload); // mSeqNo
                let ping_64 = read_u64(&mut packet.payload); // mPingTS
                let ping_ts = Rtt::u64_to_ts(ping_64);

                let pong_64 = read_u64(&mut packet.payload); // mPongTS
                let pong_ts = Rtt::u64_to_ts(pong_64);

                let now_ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("Time went backwards");

                // calculate actual rtt
                let rtt = now_ts.as_millis() - ping_ts.as_millis();
                // calculate offset out of their time, assuming, that both (ping and pong) packets had an equal travel time
                let _offset = pong_ts.as_millis() as i128 - (now_ts.as_millis() - rtt / 2) as i128;

                // println!("received rtt: {}ms with a {}ms offset", rtt, offset);
            }
            m => panic!("Rtt: sub type: {:02X} is unknown", m),
        }
        HandlePacketResult::Handled(None)
    }

    pub fn gen_ping(seq_num: u32) -> Packet {
        let mut payload: Vec<u8> = Vec::new();
        let mut offset = 0;

        let header: Header = ServiceHeader {
            service: RTT_SERVICE,
            sub_type: RTT_SUB_TYPE_PING,
            size: 8 + 4 + 8,
        }
        .into();

        // seq num
        serial_stuff::write_u32(&mut payload, &mut offset, seq_num);

        // add time
        let ping_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards");
        serial_stuff::write_u64(&mut payload, &mut offset, Rtt::ts_to_u64(&ping_ts));

        assert_eq!(offset, payload.len());
        assert_eq!(offset, header.get_payload_size());

        Packet::new_without_location(header, payload)
    }

    fn gen_pong(seq_num: u32, ping_ts: u64) -> Packet {
        let mut payload: Vec<u8> = Vec::new();
        let mut offset = 0;

        let header: Header = ServiceHeader {
            service: RTT_SERVICE,
            sub_type: RTT_SUB_TYPE_PONG,
            size: 8 + 4 + 8 + 8,
        }
        .into();

        // seq_num
        serial_stuff::write_u32(&mut payload, &mut offset, seq_num);

        // ping
        serial_stuff::write_u64(&mut payload, &mut offset, ping_ts);

        // add pong
        let pong_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        serial_stuff::write_u64(&mut payload, &mut offset, Rtt::ts_to_u64(&pong_ts));

        assert_eq!(offset, payload.len());
        assert_eq!(offset, header.get_payload_size());

        Packet::new_without_location(header, payload)
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

impl Service for Rtt {
    fn get_id(&self) -> u16 {
        RTT_SERVICE
    }

    fn handle_packet(&self, packet: Packet) -> HandlePacketResult {
        self.handle_incoming(&packet.header.into(), packet)
    }

    fn tick(&mut self, _stats: &mut StatsCollection) -> Option<Vec<Packet>> {
        let mut items: Vec<Packet> = vec![];
        if self.last_ping.elapsed().unwrap_or_default().as_secs() >= 5 {
            let item = Rtt::gen_ping(self.next_seq_num.clone());
            items.push(item);

            self.next_seq_num += 1;
            self.last_ping = SystemTime::now();
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
