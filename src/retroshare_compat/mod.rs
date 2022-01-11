use std::{env, path::PathBuf};

pub mod config_store;
pub mod ssl_key;

pub fn get_base_dir() -> PathBuf {
    // check for portable mode
    const DATA_DIR: &str = ".retroshare";
    const DATA_DIR_PORTABLE: &str = "data";
    const POTRABLE_TEST_FILE: &str = "portable";

    if env::consts::OS == "windows"
        && env::current_exe()
            .expect("can't get executable's directory")
            .join(POTRABLE_TEST_FILE)
            .exists()
    {
        println!("portable mode detected");
        return env::current_exe()
            .expect("can't get executable's directory")
            .join(DATA_DIR_PORTABLE);
    }
    dirs::home_dir()
        .expect("can't find home directory")
        .join(DATA_DIR)
}
