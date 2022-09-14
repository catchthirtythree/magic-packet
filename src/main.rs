use std::{net::{SocketAddr, UdpSocket}, process::exit};

use clap::Parser;
use magic_packet::{MacAddress, MagicPacket, MacAddressParseError, SecureON, SecureONParseError};

#[derive(Parser)]
struct Cli {
    #[clap(short, long)]
    mac: String,

    #[clap(short, long)]
    password: Option<String>,

    #[clap(short, long, default_value = "0.0.0.0:0")]
    src: String,

    // @TODO(michael): Figure out how to set defaults.
    #[clap(short, long)]
    destinations: Vec<String>,
}

fn main() -> Result<(), std::io::Error> {
    let args = Cli::parse();

    let src: SocketAddr = args.src.parse().unwrap_or_else(|_| {
        eprintln!("Invalid IP address syntax, expected: 0.0.0.0:0");
        exit(1);
    });

    let socket = UdpSocket::bind(src).unwrap_or_else(|_| {
        eprintln!("Could not bind to address: {}", src);
        exit(1);
    });

    println!("Created socket bound to: {}", src);

    socket.set_broadcast(true).unwrap_or_else(|_| {
        eprintln!("Unable to set broadcast: set_broadcast call failed.");
        exit(1);
    });

    let phys_addr: MacAddress = args.mac.parse().unwrap_or_else(|err| {
        match err {
            MacAddressParseError::InvalidLength => {
                eprintln!("Unable to parse mac address, expected: 1a:2b:3c:d4:e5:f6 or 1a-2b-3c-d4-e5-f6");
            },

            MacAddressParseError::InvalidOctet(s, octet) => {
                eprintln!("Unable to parse octet {} of '{}': '{}'", octet, args.mac, s);
            }
        }
        exit(1);
    });

    println!("Parsed outbound mac address: {}", phys_addr.to_delimited_string('-'));

    let password: Option<SecureON> = match args.password {
        Some(pass) => Some(pass.parse().unwrap_or_else(|err| {
            match err {
                SecureONParseError::InvalidLength => {
                    eprintln!("Unable to parse password, expected: 1a2b3cd4e5f6");
                },

                SecureONParseError::InvalidBytes(s, octet) => {
                    eprintln!("Unable to parse bytes {} of '{}': '{}'", octet, args.mac, s);
                }
            }
            exit(1);
        })),
        None => None
    };

    if let Some(pass) = &password {
        println!("Parsed password: {}", pass.to_string());
    }

    let packet = MagicPacket::new(&phys_addr, password);

    println!("Created magic packet: {:x?}", packet.buf);

    for destination in args.destinations {
        let dest: SocketAddr = match destination.parse() {
            Ok(dest) => dest,
            Err(_) => {
                eprintln!("Invalid IP address syntax, expected: 0.0.0.0:0");
                continue;
            }
        };

        println!("Parsed magic packet destination: {}", dest);

        let sent = match packet.send(&socket, &dest) {
            Ok(sent) => sent,
            Err(err) => {
                eprintln!("{}", err);
                continue;
            }
        };

        println!("Sent {} bytes to {}", sent, dest);
    }

    Ok(())
}
