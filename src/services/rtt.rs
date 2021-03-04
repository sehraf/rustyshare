use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{
    parser::{
        headers::{Header, ServiceHeader},
        Packet,
    },
    serial_stuff, services,
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

    pub fn handle_incoming(header: &ServiceHeader, payload: &Vec<u8>) -> Option<Vec<u8>> {
        let mut offset = 0;
        match header.sub_type {
            0x01 => {
                let seq_num = serial_stuff::read_u32(&payload, &mut offset); // mSeqNo
                let ping_64 = serial_stuff::read_u64(&payload, &mut offset); // mPingTS

                let item = Rtt::gen_pong(seq_num, ping_64);
                return Some(item);
            }
            0x02 => {
                let seq_num = serial_stuff::read_u32(&payload, &mut offset); // mSeqNo
                let ping_64 = serial_stuff::read_u64(&payload, &mut offset); // mPingTS
                let ping_ts = Rtt::u64_to_ts(ping_64);

                let pong_64 = serial_stuff::read_u64(&payload, &mut offset); // mPongTS
                let pong_ts = Rtt::u64_to_ts(pong_64);

                // this does happen
                if ping_ts > pong_ts {
                    println!("PONG {}, but the time is off ... -{:?}", seq_num, ping_ts - pong_ts);
                } else {
                    println!("PONG {} {:?}", seq_num, pong_ts - ping_ts);
                }
            }
            m => panic!("Rtt: sub type: {:02X} is unknown", m),
        }
        None
    }

    pub fn gen_ping(seq_num: u32) -> Vec<u8> {
        let mut item: Vec<u8> = Vec::new();
        let mut offset = 8; // skipp header

        let header: Header = ServiceHeader {
            service: RTT_SERVICE,
            sub_type: RTT_SUB_TYPE_PING,
            size: 8 + 4 + 8,
        }
        .into();
        item.extend_from_slice(&header.to_bytes());

        // seq num
        serial_stuff::write_u32(&mut item, &mut offset, seq_num);

        // add time
        let ping_ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards");
        serial_stuff::write_u64(&mut item, &mut offset, Rtt::ts_to_u64(&ping_ts));

        assert_eq!(offset, item.len());
        item
    }

    fn gen_pong(seq_num: u32, ping_ts: u64) -> Vec<u8> {
        let mut item: Vec<u8> = Vec::new();
        let mut offset = 8; // skipp header

        let header: Header = ServiceHeader {
            service: RTT_SERVICE,
            sub_type: RTT_SUB_TYPE_PONG,
            size: 8 + 4 + 8 + 8,
        }
        .into();
        item.extend_from_slice(&header.to_bytes());

        // seq_num
        serial_stuff::write_u32(&mut item, &mut offset, seq_num);

        // ping
        serial_stuff::write_u64(&mut item, &mut offset, ping_ts);

        // add pong
        let pong_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        serial_stuff::write_u64(&mut item, &mut offset, Rtt::ts_to_u64(&pong_ts));

        assert_eq!(offset, item.len());
        item
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

impl services::Service for Rtt {
    fn get_id(&self) -> u16 {
        RTT_SERVICE
    }

    fn handle_packet(&self, packet: Packet) -> Option<Vec<u8>> {
        return Rtt::handle_incoming(&packet.header.into(), &packet.data);
    }

    fn tick(&mut self) -> Option<Vec<Vec<u8>>> {
        let mut items: Vec<Vec<u8>> = vec![];
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
