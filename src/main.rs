use std::{
    collections::HashMap,
    convert::TryInto,
    fs::File,
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::mpsc,
    thread::sleep,
    time::{Duration, Instant},
};

use ::retroshare_compat::basics::*;

mod error;
mod model;
mod parser;
mod retroshare_compat;
mod serial_stuff;
mod services;
mod transport;
mod utils;

use ::retroshare_compat::keyring::Keyring;
use io::Write;
use model::{PeerCommand, PeerThreadCommand};
use openpgp::Cert;
use openssl::x509::X509;
use sequoia_openpgp as openpgp;
use serial_stuff::load_peers;

// fn to_string(cert: &Option<&openpgp::Cert>) -> String {
//     let s: String = match cert {
//         None => String::from("nothing"),
//         Some(v) => {
//             let mut s2: String = String::new();
//             for ua in v.userids() {
//                 // let s3: String = match ua.name() {
//                 //     Ok(v) => v.unwrap(),
//                 //     Err(_) => String::from("nothing, failed to get name"),
//                 // };
//                 if ua.name().is_err() {
//                     println!("no name");
//                 }
//                 if ua.comment().is_err() {
//                     println!("no comment");
//                 }
//                 if ua.email().is_err() {
//                     println!("no email");
//                 }
//                 if ua.uri().is_err() {
//                     println!("no uri");
//                 }
//                 let s3 = String::from_utf8_lossy(ua.value());
//                 s2.push_str(&s3);
//             }
//             {
//                 let x: &openpgp::Cert = &v;
//                 println!("{}'s has {} keys.", x.fingerprint(), x.keys().count());
//             }
//             s2.clone()
//         }
//     };
//     s
// }

fn read_location_cert(path: &Path) -> Result<X509, io::Error> {
    let full_path = path.join("keys/user_cert.pem");
    let mut file = File::open(full_path)?;

    let mut user_cert = Vec::new();
    file.read_to_end(&mut user_cert)?;

    return Ok(openssl::x509::X509::from_pem(&user_cert)?);
}

fn select_location(base_dir: &Path, keys: &Keyring) -> Option<(String, X509, Cert)> {
    const LOC_FOLDER_PREFIX: &str = "LOC06_";
    const LOC_FOLDER_PREFIX_HIDDEN: &str = "HID06_";

    // build list with valid options
    let mut locations: Vec<(String, X509, Cert)> = vec![];
    for dir in std::fs::read_dir(base_dir).expect("failed to list folder") {
        // get folder (name)
        let dir = dir.unwrap();
        let dir_name = dir.file_name().to_string_lossy().to_string();

        // check if it's a valid candidate
        if dir_name.len() != 38
            || (!dir_name.starts_with(LOC_FOLDER_PREFIX)
                && !dir_name.starts_with(LOC_FOLDER_PREFIX_HIDDEN))
        {
            continue;
        }

        // read pub key
        let cert = read_location_cert(&dir.path());
        if cert.is_err() {
            // TODO Add error handling
            continue;
        }
        let cert = cert.unwrap();

        // find priv key
        let key = keys.get_key_by_id_str(
            &String::from_utf8_lossy(
                cert.issuer_name()
                    .entries()
                    .into_iter()
                    .next()
                    .unwrap()
                    .data()
                    .as_slice(),
            ),
            true,
        );
        if key.is_none() {
            // TODO Add error handling
            continue;
        }
        let key = key.unwrap();

        // TODO
        // figure out the actual location name

        locations.push((dir_name, cert, key.clone()));
    }

    // ask user
    println!("Please select a location:");
    let mut num = 1;
    for loc in &locations {
        let name = loc.2.userids().next().unwrap().to_string();
        println!(" [{}]: '{}' by '{}'", num, loc.0, name);
        num += 1;
    }
    print!("> ");
    io::stdout().flush().unwrap();

    // read answer and return the entry
    let mut buffer = String::new();
    match io::stdin().read_line(&mut buffer) {
        Ok(len) => {
            assert!(len < 4); // 1-99 should be enough
            buffer.pop();

            // parse number
            let num_selected = buffer.parse::<usize>().expect("failed to parse input!");
            assert!(num > num_selected);

            // get key
            let loc = &locations[num_selected - 1];
            return Some(loc.clone());
        }
        Err(_) => {}
    }
    None
}

fn main() {
    let rs_base_dir = dirs::home_dir()
        .expect("can't find home directory")
        .join(".retroshare");

    // load keyring
    let mut keys = Keyring::new();
    keys.parse(&rs_base_dir);

    let (loc, localtion_path, key) = loop {
        // pick location
        let loc = select_location(&rs_base_dir, &keys).expect("no location selected");
        let localtion_path = rs_base_dir.join(&loc.0);

        println!("");
        let mut password = rpassword::prompt_password_stdout("Password: ").unwrap();

        // unlock key ...
        if let Ok(key) = retroshare_compat::ssl_key::SslKey::new().load_encrypted(
            &loc.2,
            &localtion_path,
            &password,
        ) {
            password.clear();
            break (loc, localtion_path, key);
        }
        password.clear();

        // try again!
        println!("... failed!\n");
    };

    // ... load general config ...
    let general_cfg = retroshare_compat::config_store::decryp_file(
        &localtion_path.join("config/general.cfg"),
        &key.1,
    )
    .expect("failed to load peers.cfg");
    serial_stuff::parse_general_cfg(&general_cfg);

    // ... and load location ...
    let mut peers_cfg = retroshare_compat::config_store::decryp_file(
        &localtion_path.join("config/peers.cfg"),
        &key.1,
    )
    .expect("failed to load peers.cfg");

    // ... and peer infos
    let friends = load_peers(&mut peers_cfg, &keys);

    // build own id
    let hex = hex::decode(&loc.0[6..]).expect("Decoding failed");
    let peer_id: [u8; 16] = hex.try_into().expect("failed to convert!"); // SSL_ID
    let peer_id = PeerId(peer_id);

    // init data core
    let mut core = model::DataCore::new(key.0, key.1, friends, &peer_id);
    let own_ips = core.get_own_location().get_ips().0.clone(); // TODO

    // setup listener
    let port = own_ips
        .iter()
        .find(|ip| {
            if let SocketAddr::V4(v4) = ip.addr.0 {
                return v4.ip().is_private();
            }
            false
        })
        .expect("can't find local address!")
        .addr
        .0
        .port();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port); // 9926
    let (listener_tx, listener_rx) = mpsc::channel();
    let listener = transport::listener::Listener::new(addr, core.get_tx(), listener_rx).unwrap();

    let mut stats: utils::simple_stats::StatsCollection = (Instant::now(), HashMap::new());

    // tick forever

    // stats counter
    let mut counter = 0;
    const MAX_COUNTER: u32 = 80;

    // sleep time
    let mut now: Instant;
    const TARGET_INTERVAL: Duration = Duration::from_millis(25);

    while core.tick(&mut stats) {
        now = Instant::now();

        counter += 1;
        if counter > MAX_COUNTER {
            counter = 0;

            utils::simple_stats::print(&stats);
            stats.0 = Instant::now();
            stats.1.clear();
        }

        // timing stuff
        // main loop should run every TARGET_INTERVAL
        let loop_duration = Instant::now() - now;
        if loop_duration >= TARGET_INTERVAL {
            continue;
        }
        let sleep_duration = TARGET_INTERVAL - loop_duration;
        // println!("main loop execution took {}us sleeping for {}us", &loop_duration.as_millis(), &sleep_duration.as_millis());
        sleep(sleep_duration);
    }

    // shutdown listener
    listener_tx
        .send(PeerCommand::Thread(PeerThreadCommand::Stop))
        .expect("failed to communicate with listener");
    listener.join().unwrap();
}
