rustyshare - It compiles!
===============================

| So i wanted to learn Rust and though it might be a *good* idea to implement RetroShare in Rust as an exercise.
| Some parts might still look "c like" and some design pattern might be stupid or "anti Rust".

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
 - Find a painless way to support RS's TLV / sane serialization mixture.
 - try out nom for TLV
 - consider (basic) REST api support.
 - async support, probably not gonna happen soon
 - turtle fast path, directly sending data to the target peer, skipping the core.
 - experiment with rustls instead of openssl