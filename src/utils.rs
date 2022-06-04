use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};

pub mod simple_stats {
    use std::{collections::HashMap, time::Instant};

    pub type StatsPrinter = fn(i32) -> String;
    pub type StatEntry = HashMap<String, (StatsPrinter, i32)>;
    pub type StatsCollection = (Instant, HashMap<String, StatEntry>);

    #[allow(dead_code)]
    pub fn print(data: &StatsCollection) {
        println!("Stats:");
        println!(
            " over the last {:.02}ms",
            (Instant::now() - data.0).as_millis()
        );
        for group in data.1.iter() {
            print!(" - {}:", group.0);
            let entries = group.1;

            // sort entries
            let mut as_vec: Vec<_> = entries.iter().collect();
            as_vec.sort_by_key(|entry| entry.0);

            for entry in as_vec {
                print!(" {}={}", entry.0, entry.1 .0(entry.1 .1));
            }
            print!("\n")
        }
    }
}

pub mod units {
    #[allow(dead_code)]
    pub fn pretty_print_bytes(bytes: u64) -> String {
        let mut b = bytes as f64;
        let mut unit_index = 0;

        let units: Vec<String> = vec![
            String::from("B"),
            String::from("kB"),
            String::from("mB"),
            String::from("gB"),
            String::from("tB"),
            String::from("pB"),
        ];

        while b > 1024.0 && unit_index < units.len() {
            b /= 1024.0;
            unit_index += 1;
        }

        format!("{:.2} {}", b, units[unit_index])
    }
}

enum TimerType {
    OneShot(bool),
    Repeating(Duration),
}

/// A simple timer that can be used for recurring events or for a single one-shot event
pub struct Timer {
    end: SystemTime,
    ty: TimerType,
}

impl Timer {
    /// Creates a recurring timer (first trigger after `duration`)
    pub fn new(duration: Duration) -> Self {
        let expired = SystemTime::now()
            .checked_add(duration)
            .expect("failed to add time");
        Self {
            end: expired,
            ty: TimerType::Repeating(duration),
        }
    }

    /// Creates a recurring timer (first trigger after `first_timeout` instead of `duration`)
    pub fn new_soon(duration: Duration, first_timeout: Duration) -> Self {
        let expired = SystemTime::now()
            .checked_add(first_timeout)
            .expect("failed to add time");
        Self {
            end: expired,
            ty: TimerType::Repeating(duration),
        }
    }

    /// Creates a one-shot timer
    pub fn new_one_shot(duration: Duration) -> Self {
        let expired = SystemTime::now()
            .checked_add(duration)
            .expect("failed to add time");
        Self {
            end: expired,
            ty: TimerType::OneShot(false),
        }
    }

    /// Checks if the timer is expired.
    /// 
    /// Also rearms recurring timers.
    pub fn expired(&mut self) -> bool {
        if SystemTime::now() >= self.end {
            match &mut self.ty {
                TimerType::OneShot(true) => false,
                TimerType::OneShot(triggered) => {
                    *triggered = true;
                    true
                }
                TimerType::Repeating(duration) => {
                    self.end = SystemTime::now()
                        .checked_add(*duration)
                        .expect("failed to add time");
                    true
                }
            }
        } else {
            false
        }
    }
}

// FIXME? probably not the most performant way ...
pub type Timers = HashMap<String, Timer>;

// #[macro_export]
// macro_rules! check_timer {
//     ($timers:expr, $identifier:expr, $ty:expr) => {
//         $timers.entry($identifier).or_insert($ty).expired()
//     };
// }
