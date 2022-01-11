pub mod simple_stats {
    use std::{collections::HashMap, time::Instant};

    pub type StatsPrinter = fn(i32) -> String;
    pub type StatEntry = HashMap<String, (StatsPrinter, i32)>;
    pub type StatsCollection = (Instant, HashMap<String, StatEntry>);

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
