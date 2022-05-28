use controller::CoreController;
use flexi_logger::{LevelFilter, LogSpecification};
use log::warn;
use std::{
    convert::TryInto,
    fs::File,
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
};
use tokio::{self, select};

use ::retroshare_compat::basics::*;

mod controller;
mod error;
mod gxs;
mod low_level_parsing;
mod model;
mod retroshare_compat;
mod serial_stuff;
mod services;
mod transport_ng;
mod utils;
mod webui;

use ::retroshare_compat::keyring::Keyring;
use io::Write;
use openssl::x509::X509;
use sequoia_openpgp as openpgp;
use serial_stuff::load_peers;

#[allow(unused_braces)]
fn read_location_cert(path: &Path) -> Result<X509, io::Error> {
    // fn read_location_cert(path: &Path) -> Result<Certificate, RsError> {
    let full_path = path.join("keys/user_cert.pem");
    let mut file = File::open(full_path)?;

    let mut user_cert = Vec::new();
    file.read_to_end(&mut user_cert)?;

    Ok(openssl::x509::X509::from_pem(&user_cert)?)
}

#[allow(unused_braces)]
fn select_location(base_dir: &Path, keys: &Keyring) -> Option<(String, X509, openpgp::cert::Cert)> {
    const LOC_FOLDER_PREFIX: &str = "LOC06_";
    const LOC_FOLDER_PREFIX_HIDDEN: &str = "HID06_";

    // build list with valid options
    let mut locations = vec![];
    // let mut locations: Vec<(String, Certificate, Cert)> = vec![];
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
                cert
                    // .0
                    .issuer_name()
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
        let key = key.unwrap().to_owned();

        // TODO
        // figure out the actual location name

        locations.push((dir_name, cert, key));
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
            if len >= 5 {
                return None;
            }

            let buffer = buffer.trim();

            // parse number
            let num_selected = buffer.parse::<usize>().ok()?;
            assert!(num > num_selected);

            // get key
            let loc = &locations[num_selected - 1];
            return Some(loc.to_owned());
        }
        Err(err) => warn!("failed {err}"),
    }
    None
}

#[tokio::main]
async fn main() {
    let mut builder = LogSpecification::builder();
    builder
        // .module("rustyshare::controller::connected_peer", LevelFilter::Debug)
        // .module("rustyshare::controller", LevelFilter::Trace)
        // .module("rustyshare::gxs", LevelFilter::Trace)
        // .module("rustyshare::gxs::gxsid", LevelFilter::Trace)
        // .module("rustyshare::services", LevelFilter::Trace)
        .module("rustyshare::services::heartbeat", LevelFilter::Warn)
        .module("rustyshare::services::bwctrl", LevelFilter::Warn)
        // .module("rustyshare::services::chat", LevelFilter::Debug)
        .module("rustyshare::services::gxs_id", LevelFilter::Trace)
        // .module("rustyshare::services::turtle", LevelFilter::Trace)
        // .module("sequoia_openpgp", LevelFilter::Trace)
        // .module("actix", LevelFilter::Trace)
        .module("actix_web", LevelFilter::Trace)
        .default(LevelFilter::Info);
    flexi_logger::Logger::with(builder.finalize())
        // .log_to_file(FileSpec::default())
        // .print_message()
        // .write_mode(WriteMode::BufferAndFlush)
        // .duplicate_to_stderr(Duplicate::All)
        // .log_to_stderr()
        .start()
        .expect("failed to start logger");

    // Tokio debugging
    // console_subscriber::init();

    let rs_base_dir = retroshare_compat::get_base_dir();

    // load keyring
    let mut keys = Keyring::new();
    keys.parse(&rs_base_dir);

    let (loc, localtion_path, ssl_key, (gxs_id_db, _gxs_forum_db)) = loop {
        // pick location
        let loc = match select_location(&rs_base_dir, &keys) {
            Some(a) => a,
            None => continue,
        };
        let localtion_path = rs_base_dir.join(&loc.0);

        println!("");
        let mut password = rpassword::prompt_password_stdout("Password: ").unwrap();

        // unlock key ...
        match retroshare_compat::ssl_key::SslKey::new().load_encrypted(
            &loc.2,
            &localtion_path,
            &password,
        ) {
            Ok((key, gxs)) => {
                password.clear();
                break (loc, localtion_path, key, gxs);
            }
            Err(why) => {
                warn!("{}", why);
            }
        }
        password.clear();

        // try again!
        println!("... failed!\n");
    };

    // ... load general config ...
    let mut general_cfg = retroshare_compat::config_store::decryp_file(
        &localtion_path.join("config/general.cfg"),
        ssl_key.to_owned(),
    )
    .expect("failed to load peers.cfg");
    serial_stuff::parse_general_cfg(&mut general_cfg);

    // ... and load location ...
    let mut peers_cfg = retroshare_compat::config_store::decryp_file(
        &localtion_path.join("config/peers.cfg"),
        ssl_key.to_owned(),
    )
    .expect("failed to load peers.cfg");

    // ... and peer infos
    let friends = load_peers(&mut peers_cfg, &keys);

    // build own id
    let hex = hex::decode(&loc.0[6..]).expect("Decoding failed");
    let peer_id: [u8; 16] = hex.try_into().expect("failed to convert!"); // SSL_ID
    let peer_id = Arc::new(SslId(peer_id));

    // init data core
    let data_core = model::DataCore::new(ssl_key, friends, peer_id, gxs_id_db).await;
    let own_ips = data_core.get_own_location().get_ips().0.clone(); // TODO

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
    let _addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);

    // setup webui
    let web = webui::actix::run_actix(data_core.clone());

    // enter main loop
    let mut core = CoreController::new(data_core).await;
    let fut = core.run();

    // run everything
    select! {
        _ = web => {},
        _ = fut => {},
    }
}
