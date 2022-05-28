use rusqlite::Result;

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
            $(pub $var_name: $var_type),+
        }

        impl crate::gxs::sqlite::FromSql for $struct_name {
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
