use serde::Serialize;

#[cfg(feature = "webui_actix")]
pub mod actix;

pub(self) mod identity;
pub(self) mod msgs;
pub(self) mod peers;

#[derive(Serialize)]
pub struct RetVal<S> {
    retval: S,
}

#[macro_export]
macro_rules! gen_webui_param_type {
    ($name:ident, $($inner:ident: $ty:ty),+) => {
        #[derive(serde::Deserialize)]
        pub struct $name {
            $($inner: $ty,)+
        }
    };
}

#[macro_export]
macro_rules! gen_webui_return_type {
    ($name:ident, $inner:ident, $ty:ty) => {
        #[derive(serde::Serialize)]
        pub struct $name {
            retval: bool,
            $inner: $ty,
        }
    };
}
