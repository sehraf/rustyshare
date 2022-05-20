.. role:: strike
    :class: strike

rustyshare - It compiles!
===============================

| So i wanted to learn Rust and though it might be a *good* idea to implement RetroShare in Rust as an exercise.
| Some parts might still look "c like" and some design pattern might be stupid or "anti Rust".

Update 2 - *async/await and TLV*:
 - finally managed to get TLV wroking with serde. Wasn't that hard after all - once you know how to do it.
    - it's quite easy now, you only have to deal with
       - `Tlv` generic TLV type with fixed length content (e.g. a struct)
       - `Tlv2` generic TLV type with variable length content (e.g. a vector)
       - `TlvSet` generic TLV set
       - `TlvMap` generic TLV map
       - `TlvMapWithPair` generic TLV map that wrapps both `Key` and `Value` in a `TlvGenericPairRef` ...
       - also `TlvIpAddress` requires extra work since the same packet/tag can contain a IPv4 or IPv6 TlvIpAddress annd you have to check the inner tag to find out
       - also `TlvSecurityKeySet` requires extra work since private and public keys are the same and you have to check the key flags after serializing it
 - added support for sqlite(-cipher) (very basic)
 - added support for the REST api (using actix), not much is implemented yet
    - also the RsNewWebUi doesn't use `content-type` so actix will complain (complain == doen't do anything)
       - can be fixed in RsNewWebUi by adding `headers['Content-type'] = 'application/json';` in rswebui_
 - removed any manual serialisation (looking at you `serial_stuff.rs`)
 - stubbed out `chat` service
    - currently all available lobbies are joined and both events and messages are logged

.. _rswebui: https://github.com/RetroShare/RSNewWebUI/blob/master/webui-src/app/rswebui.js#L30

Update 1 - *Fast as a turtle*:
 - Added/factored out `retroshare_compat` lib for handling wire format and similar.
 - Implemented discovery to receive ip updates.
 - Implemented turtle (currently only forwards generic tunnels).
 - Slice format is used whenever sending.

What it can do:
 - use (load and decrypt) existing (PGP) key ring and locations
 - parses some aspects from peers.cfg 
 - parses general.cfg (but doesn't care about its content)
 - connect to peers (tcp only)
 - understand "new" slice format
 - listens on the location's port for incoming connections
    - currently broken for unknown reasons: *tls_post_process_client_hello:no shared cipher* which is a lie!
 - supports the following services:
    - **bwctrl**: Not sure if useful, make you appear in peers stats window.
    - **discovery**: Partly implemented to get up to date ip information from your friends.
    - **heartbeat**: Comparable to rtt just without time stamps
    - **rtt**: Simple ping/pong protocol 
    - **service_info**: Tell peers which services are available (kind of required for anything)  
    - **status**: Tell peers that we are online (makes you appear green on their end)
    - **turtle**: Able to forward (generic) tunnel data.

What it can't do:
 - basically everything else
 - peers are not verified (!!)
 - nothing is written/stored

What is planned next? *(tentative)*
 - :strike:`Find a painless way to support RS's TLV / sane serialization mixture.``
 - :strike:`try out nom for TLV``
 - consider (basic) REST api support.
 - async support, probably not gonna happen soon
 - turtle fast path, directly sending data to the target peer, skipping the core.
 - experiment with rustls instead of openssl

What else is there?
 - There is Xeres_! It's a RetroShare client written in Java

.. _Xeres: https://xeres.io/