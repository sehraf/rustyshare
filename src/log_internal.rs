use std::fmt::Debug;

#[cfg(feature = "tracing")]
use flexi_logger::trc::LogSpecAsFilter;
use flexi_logger::{
    writers::ArcFileLogWriter, writers::FileLogWriter, Duplicate, FileSpec, LevelFilter,
    LogSpecification, WriteMode,
};
#[cfg(feature = "tracing")]
use tracing_subscriber::FmtSubscriber;

// struct Duplicator {
//     out1: std::io::Stderr,
//     out2: ArcFileLogWriter,
// }
// impl Duplicator {
//     fn new(flw: ArcFileLogWriter) -> Self {
//         Self {
//             out1: std::io::stderr(),
//             out2: flw,
//         }
//     }
// }
// impl std::io::Write for Duplicator {
//     fn flush(&mut self) -> Result<(), std::io::Error> {
//         self.out1.flush().ok();
//         self.out2.flush()
//     }
//     fn write(&mut self, buffer: &[u8]) -> Result<usize, std::io::Error> {
//         self.out1.write(buffer).ok();
//         self.out2.write(buffer)
//     }
// }

pub(crate) fn init_logger() {
    #[allow(unused_variables)]
    let log_specification = {
        let mut builder = LogSpecification::builder();
        builder
            // .module(
            //     "retroshare_compat::gxs::sqlite::database",
            //     LevelFilter::Trace,
            // )
            // .module("rustyshare::controller::connected_peer", LevelFilter::Debug)
            // .module("rustyshare::controller", LevelFilter::Trace)
            .module("rustyshare::gxs", LevelFilter::Debug)
            // .module("rustyshare::gxs::gxsid", LevelFilter::Debug)
            // .module("rustyshare::gxs::nxs_transactions", LevelFilter::Debug)
            // .module("rustyshare::services", LevelFilter::Trace)
            .module("rustyshare::services::heartbeat", LevelFilter::Warn)
            .module("rustyshare::services::bwctrl", LevelFilter::Warn)
            // .module("rustyshare::services::chat", LevelFilter::Trace)
            // .module("rustyshare::services::gxs_id", LevelFilter::Debug)
            // .module("rustyshare::services::turtle", LevelFilter::Trace)
            // .module("actix", LevelFilter::Trace)
            .module("actix_web", LevelFilter::Trace)
            .default(LevelFilter::Info);
        builder.finalize()
    };
    println!("using log_specification: {}", log_specification.to_string());

    /*
    #########################
    flexi_logger
    #########################
    */

    #[cfg(not(feature = "tracing"))]
    {
        let handle = flexi_logger::Logger::with(log_specification)
            // use async output
            .write_mode(WriteMode::Async)
            // write to log file (overwrite old one)
            .log_to_file(FileSpec::default().suppress_timestamp())
            // log log file name
            .print_message()
            // also print to stderr
            .duplicate_to_stderr(Duplicate::All)
            .start()
            .expect("failed to start logger");

        // leak handle to keep it alive for the rest of the program
        let x = Box::new(handle);
        let _ = Box::leak(x);
    }
    
    /*
    #########################
    flexi_logger + tracing
    #########################
    */

    // let subscriber_builder = FmtSubscriber::builder()
    //     // .with_writer(move || file_writer.clone())
    //     // .with_writer(move || Duplicator::new(file_writer.clone()))
    //     .without_time()
    //     .with_level(true)
    //     .with_target(true)
    //     .with_thread_ids(true)
    //     .with_thread_names(true)
    //     .with_env_filter(LogSpecAsFilter(log_specification));

    // // Get ready to trace
    // tracing::subscriber::set_global_default(subscriber_builder.finish())
    //     .expect("setting default subscriber failed");

    /*
    #########################
    tracing_log
    #########################
    */

    // tracing_log::LogTracer::init().expect("failed to start logger");

    /*
    #########################
    tracing_subscriber
    #########################
    */
    #[cfg(feature = "tracing")]
    {
        // Configure a custom event formatter
        let format = tracing_subscriber::fmt::format()
            .without_time()
            .with_level(true)
            .with_target(true)
            .with_thread_ids(true)
            .with_thread_names(true);

        // Create a `fmt` subscriber that uses our custom event format, and set it
        // as the default.
        tracing_subscriber::fmt()
            .event_format(format)
            .with_env_filter(log_specification.to_string())
            .init();
    }

    /*
    #########################
    console_subscriber
    #########################
    */

    // Tokio debugging
    #[cfg(tokio_unstable)]
    console_subscriber::init();
}
