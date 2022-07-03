use rusqlite::Result;

pub mod database;
pub mod types;

pub trait FromSqlRs
where
    Self: Sized,
{
    fn get_columns() -> Vec<(String, String)>;
    fn from_row(row: &rusqlite::Row) -> Result<Self>;
    fn to_row(&self) -> Vec<&dyn rusqlite::ToSql>;
}

#[macro_export]
macro_rules! gen_db_type {
    ($struct_name:ident $(< $const:tt $lt2:ident : $clt:tt >)?,
        $([$var_name:ident: $var_type:tt $(< $lt3:ident >)?, $db_field:expr]),+
        ,
    ) => {
        // do not generate serde code! These aren't straight forward serializable
        #[derive(Debug, Default, Clone)]
        pub struct $struct_name$(<$const $lt2: $clt>)? {
            $(pub $var_name: $var_type $(< $lt3 >)?),+
        }

        impl crate::gxs::sqlite::FromSqlRs for $struct_name {
            fn get_columns() -> Vec<(String, String)> {
                let mut index = 0; // start with 0 and add 1 first
                // create fields
                vec![
                    $(
                        ($db_field, {
                            index += 1;
                            String::from("?") + &index.to_string()
                        })
                    ),+
                ].into_iter()
                // remove empty ones
                .filter(|(s, _)| !s.is_empty())
                // convert to string
                .map(|(s, t)| (s.to_string(), t))
                .collect()
            }

            // we end with index += 1, which rustc warns about
            #[allow(unused_assignments)]
            fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
                // load fields from from
                let mut index = 0;
                $(
                    let $var_name = if !$db_field.is_empty() {
                        let tmp = row.get(index)?;
                        index += 1;
                        tmp
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

            fn to_row(&self) -> Vec<& dyn rusqlite::ToSql>{
                let mut row = vec![];
                $(
                    if !$db_field.is_empty() {
                        row.push(&self.$var_name as &dyn rusqlite::ToSql);
                    }
                )+

                row
            }
        }
    };
}

#[macro_export]
macro_rules! impl_sql_for_bitflags {
    ($name:ident) => {
        impl rusqlite::types::FromSql for $name {
            fn column_result(
                value: rusqlite::types::ValueRef<'_>,
            ) -> rusqlite::types::FromSqlResult<Self> {
                let value = value.as_i64()? as u32;
                Ok($name::from_bits(value).unwrap_or_else(|| {
                    log::warn!("Invalid bits {:#X} for {}", value, stringify!($name));
                    
                    // log::warn!("{}", std::backtrace::Backtrace::capture());
                    
                    $name::empty()
                }))
            }
        }

        impl rusqlite::types::ToSql for $name {
            fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
                Ok(self.bits().into())
            }
        }
    };
}
