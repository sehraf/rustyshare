rustyshare - It compiles!
===============================

| So i wanted to learn Rust and though it might be a *good* idea to implement RetroShare in Rust as an exercise.
| Some parts might still look "c like" and some desing pattern might be stupid or "anti Rust".

What it can do:
 - use (load and decrypt) existing (PGP) key ring and locations
 - parses some aspects from peers.cfg 
 - parses general.cfg (but doesn't care about its content)
 - connect to peers (tcp only)
 - understand "new" slice format
 - listens on the location's port for incoming connections
    - currently broken for unkown reasons: *tls_post_process_client_hello:no shared cipher* which is a lie!
 - supports the following services:
    - **service_info**: Tell peers which services are available (kind of required for anything)
    - **rtt**: simple ping/pong protocol
    - **heartbeat**: comparable to rtt just without time stamps
    - **status**: Tell peers that we are online (makes you appear green on their end)

What it shouldn't do:
 - Serialiser/Parses are hand written which was a PITA! 
 - Yes, underscore ('_') is the don't care operator, which was regulary used to trash useless stuff ...
 - Also notice the type which is *1* all the time ...

.. code-block:: rust

    // RsTlvGenericMapRef<uint32_t, RsServiceInfo> FUN!
    let _ = serial_stuff::read_u16(payload, &mut offset); // type = 1
    let _ = serial_stuff::read_u32(payload, &mut offset); // len

    while offset < payload.len() {
        // RsTlvGenericPairRef moar FUN
        let _ = serial_stuff::read_u16(payload, &mut offset); // type = 1
        let _ = serial_stuff::read_u32(payload, &mut offset); // len

        // RsTlvParamRef we are getting there ...
        // key
        let _ = serial_stuff::read_u16(payload, &mut offset); // type = 1
        let _ = serial_stuff::read_u32(payload, &mut offset); // len
        let servcie_num = serial_stuff::read_u32(payload, &mut offset);
        // value
        let _ = serial_stuff::read_u16(payload, &mut offset); // type = 1
        let _ = serial_stuff::read_u32(payload, &mut offset); // len

What it can't do:
 - basically everything else
 - peers are not verified (!!)
 - nothing is written/stored

What is planned next? *(tentative)*
 - Get proc macros going for a serde like serialiser.
 - Factor out the retroshare_compat stuff in a separate crate.
 - Implement discovery v2.
 - Implement at least one forwarding service (maybe turtle?).
 - Support sending in slice format.
 - Rant about the fact that this is way more memory/thread/everything safe than C++ RetroShare.
 - Implement noise protocl to be finally the supperior program and rant even more.
 - Let people know that not everything (above) is meant seriously.