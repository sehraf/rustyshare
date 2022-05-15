// use crate::serde;

// macro_rules! gen_serial {
//     () => {};
//     ($struct_name:ident, $($element: ident: $ty: ty),*) => {
//         struct $struct_name {
//             $($element: $ty),*
//         }

//         pub fn from_retroshare_wire(data: Vec<u8>) -> $struct_name {
//             $struct_name {
//                 $($element: <$ty>::default()),*
//             }
//         }
//     };
//     // ($var_name:ident, $typ:ident ) => {
//     //     let $var_name: $typ = from_retroshare_wire(data).expect("failed to read "$var_name);
//     // };
// }
// macro_rules! gen_serial {
//     () => {};
//     ($struct_name:ident, $($tail:tt)*) => {
//         struct $struct_name {
//             gen_serial!(@members $($tail)* -> ());
//         }

//         // pub fn from_retroshare_wire(data: Vec<u8>) -> $struct_name {
//         //     $struct_name {
//         //     gen_serial!(@from $($tail)*);
//         //     }
//         // }

//         // pub fn to_retroshare_wire(data: $struct_name) -> Vec<u8> {
//         //     let mut out = Vec<u8>::new();
//         //     gen_serial!(@to $($tail)*);
//         //     out
//         // }
//     };
//     (@members $element: ident: $ty: ty, $($tail:tt)*) => {
//         $element: $ty,
//         gen_serial!(@members $($tail)*);
//     };
//     (@members [$tag:expr] $element: ident: $ty: ty, $($tail:tt)*) => {
//         concat!("// tag: ", stringify!($tag));
//         $element: $ty,
//         gen_serial!(@members $($tail)*);
//     };
// }

// macro_rules! gen_members {
//     () => {};
//     ($element: ident: $ty: ty,) => {
//         $element: $ty,
//     };
//     ([$tag:expr] $element: ident: $ty: ty,) => {
//         concat!("// tag: ", stringify!($tag));
//         $element: $ty,
//     };
// }

// macro_rules! gen_from {
//     () => {};
//     ($element: ident: $ty: ty,) => {
//         $element: $ty,
//     };
//     ([$tag:expr] $element: ident: $ty: ty,) => {
//         concat!("// tag: ", stringify!($tag));
//         $element: $ty,
//     };
// }

// macro_rules! gen_to {
//     () => {};
//     ($element: ident: $ty: ty,) => {
//         $element: $ty,
//     };
//     ([$tag:expr] $element: ident: $ty: ty,) => {
//         concat!("// tag: ", stringify!($tag));
//         $element: $ty,
//     };
// }

gen_serial!(FooBar, 
    a: usize, 
    b: String,
    [0x1072] c: String, 
);
