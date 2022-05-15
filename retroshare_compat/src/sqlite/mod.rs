use std::path::PathBuf;

use log::{debug, warn};
use rusqlite::{Connection, Result};

use crate::gxs::{GxsGrpMetaData, GxsMsgMetaData};

pub trait FromSql
where
    Self: Sized,
{
    fn get_columns() -> Vec<String>;
    fn from_row(row: &rusqlite::Row) -> Result<Self>;
}

#[macro_export]
macro_rules! gen_db_type {
    ($struct_name:ident,
        $([$var_name:ident: $var_type:ty, $db_field:expr]),+
        ,
    ) => {
        #[derive(Debug, Default, Serialize, Deserialize)]
        pub struct $struct_name {
            $($var_name: $var_type),+
        }

        impl FromSql for $struct_name {
            fn get_columns() -> Vec<String> {
                // create fields
                vec![
                    $(
                        $db_field
                    ),+
                ].into_iter()
                // remove empty ones
                .filter(|s| !s.is_empty())
                // convert to string
                .map(|s| s.to_string())
                .collect()
            }

            // we end with index += 1, which rustc warns about
            #[allow(unused_assignments)]
            fn from_row(row: &rusqlite::Row) -> Result<Self> {
                // load fields from from
                let mut index = 0;
                $(
                    let $var_name = if !$db_field.is_empty() {
                        index += 1;
                        row.get(index - 1)?
                    } else {
                        <$var_type>::default()
                    };
                )+

                // build struct
                Ok($struct_name {
                    $(
                        $var_name
                    ),+
                })
            }
        }
    };
}

#[derive(Debug)]
pub struct DbConnection {
    db: Connection,
}

impl DbConnection {
    pub fn new(path: PathBuf, passwd: &str) -> Result<Self> {
        let db = Connection::open(path)?;
        db.pragma_update(None, "key", passwd)?;

        Ok(DbConnection { db })
    }

    pub fn get_grp_meta(&self) -> Result<Vec<GxsGrpMetaData>> {
        let stm =
            String::from("SELECT ") + &GxsGrpMetaData::get_columns().join(",") + " FROM GROUPS";
        debug!(
            "querering {stm} on {:?}",
            self.db.path().unwrap().file_name()
        );
        let mut stm = self.db.prepare(&stm)?;
        let entries = stm
            .query_map([], |row| GxsGrpMetaData::from_row(row))?
            .filter_map(|e| match e {
                Ok(e) => Some(e),
                Err(e) => {
                    warn!("{e:?}");
                    None
                }
            })
            .collect();
        Ok(entries)
    }

    pub fn get_grp_msg(&self) -> Result<Vec<GxsMsgMetaData>> {
        let stm =
            String::from("SELECT ") + &GxsMsgMetaData::get_columns().join(",") + " FROM MESSAGES";
        debug!(
            "querering {stm} on {:?}",
            self.db.path().unwrap().file_name()
        );
        let mut stm = self.db.prepare(&stm)?;
        let entries = stm
            .query_map([], |row| GxsMsgMetaData::from_row(row))?
            .filter_map(|e| match e {
                Ok(e) => Some(e),
                Err(e) => {
                    warn!("{e:?}");
                    None
                }
            })
            .collect();
        Ok(entries)
    }
}
