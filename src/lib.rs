use std::{str::FromStr, net::{UdpSocket, SocketAddr}};

pub struct MacAddress {
    addr: [u8; 6],
}

impl MacAddress {
    pub fn new(addr: [u8; 6]) -> Self {
        Self { addr }
    }

    pub fn to_delimited_string(&self, del: char) -> String {
        let addr_iter = self.addr.iter();
        let byte_str: Vec<String> = addr_iter.map(|b| format!("{:x}", b)).collect();
        format!("{}", byte_str.join(&del.to_string()))
    }
}

#[derive(Debug)]
pub enum MacAddressParseError {
    InvalidLength,
    InvalidOctet(String, usize),
}

impl FromStr for MacAddress {
    type Err = MacAddressParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut addr: [u8; 6] = [0xff; 6];
        let str_split: Vec<&str> = s.split(|c| c == ':' || c == '-').collect();

        if str_split.len() != 6 {
            return Err(MacAddressParseError::InvalidLength);
        }

        for i in 0..str_split.len() {
            match u8::from_str_radix(str_split[i], 16) {
                Ok(hex) => addr[i] = hex,
                Err(_) => {
                    let invalid_str = String::from(str_split[i]);
                    let bad_octet = i + 1;
                    return Err(MacAddressParseError::InvalidOctet(invalid_str, bad_octet))
                }
            }
        }

        Ok(MacAddress::new(addr))
    }
}

#[cfg(test)]
mod mac_address_tests {
    use crate::MacAddress;

    #[test]
    fn test_mac_address_new() {
        let dummy_addr = [0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0];
        let mac_address = MacAddress::new(dummy_addr);
        assert_eq!(mac_address.addr, dummy_addr);
    }

    #[test]
    fn test_mac_address_from_delimited_string_colon() {
        let dummy_addr = [0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0];
        let dummy_addr_as_str = "a0:b0:c0:d0:e0:f0";
        let mac_address: MacAddress = dummy_addr_as_str.parse().unwrap();
        assert_eq!(mac_address.addr, dummy_addr);
    }

    #[test]
    fn test_mac_address_from_delimited_string_hyphen() {
        let dummy_addr = [0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0];
        let dummy_addr_as_str = "a0-b0-c0-d0-e0-f0";
        let mac_address: MacAddress = dummy_addr_as_str.parse().unwrap();
        assert_eq!(mac_address.addr, dummy_addr);
    }

    #[test]
    fn test_mac_address_to_delimited_string_colon() {
        let dummy_addr = [0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0];
        let mac_address = MacAddress::new(dummy_addr);
        let dummy_addr_as_str = String::from("a0:b0:c0:d0:e0:f0");
        assert_eq!(mac_address.to_delimited_string(':'), dummy_addr_as_str);
    }

    #[test]
    fn test_mac_address_to_delimited_string_hyphen() {
        let dummy_addr = [0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0];
        let mac_address = MacAddress::new(dummy_addr);
        let dummy_addr_as_str = String::from("a0-b0-c0-d0-e0-f0");
        assert_eq!(mac_address.to_delimited_string('-'), dummy_addr_as_str);
    }
}

pub struct MagicPacket {
    pub buf: Vec<u8>,
}

impl MagicPacket {
    /// The first six bytes are 0xff.
    const OFFSET: usize = 6;

    /// The number of times the mac address gets repeated.
    const REPETITIONS: usize = 16;

    pub fn new(mac: &MacAddress, password: Option<SecureON>) -> Self {
        match password {
            None => MagicPacket::create(mac),
            Some(pass) => MagicPacket::create_with_password(mac, pass)
        }
    }

    fn create(mac: &MacAddress) -> Self {
        let mut buf = vec![0xff; 102];
        MagicPacket::append_mac_address(&mut buf, &mac);
        Self { buf }
    }

    fn create_with_password(mac: &MacAddress, pass: SecureON) -> Self {
        let mut buf = vec![0xff; 108];
        MagicPacket::append_mac_address(&mut buf, &mac);
        MagicPacket::append_password(&mut buf, &mac, &pass);
        Self { buf }
    }

    fn append_mac_address(buf: &mut Vec<u8>, mac: &MacAddress) {
        for i in 0..(MagicPacket::REPETITIONS * mac.addr.len()) {
            let buf_offset = i + MagicPacket::OFFSET;
            let mac_addr_offset = i % mac.addr.len();
            buf[buf_offset] = mac.addr[mac_addr_offset];
        }
    }

    fn append_password(buf: &mut Vec<u8>, mac: &MacAddress, password: &SecureON) {
        for i in 0..(password.bytes.len()) {
            let buf_offset = i + MagicPacket::OFFSET + MagicPacket::REPETITIONS * mac.addr.len();
            buf[buf_offset] = password.bytes[i];
        }
    }

    pub fn send(&self, sock: &UdpSocket, dest: &SocketAddr) -> Result<usize, std::io::Error> {
        sock.send_to(&self.buf, dest)
    }
}

#[cfg(test)]
mod magic_packet_tests {
    use crate::{MacAddress, MagicPacket, SecureON};

    #[test]
    fn test_magic_packet_new() {
        let dummy_addr = MacAddress::new([0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0]);
        let packet = MagicPacket::new(&dummy_addr, None);
        let expected_buf = [
            255, 255, 255, 255, 255, 255,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240
        ];
        assert_eq!(packet.buf.len(), 102);
        assert_eq!(packet.buf, expected_buf);
    }

    #[test]
    fn test_magic_packet_new_with_password() {
        let dummy_addr = MacAddress::new([0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0]);
        let password = SecureON::new([0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0]);
        let packet = MagicPacket::new(&dummy_addr, Some(password));
        let expected_buf = [
            255, 255, 255, 255, 255, 255,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            160, 176, 192, 208, 224, 240,
            240, 224, 208, 192, 176, 160
        ];
        assert_eq!(packet.buf.len(), 108);
        assert_eq!(packet.buf, expected_buf);
    }
}

pub struct SecureON {
    bytes: [u8; 6],
}

impl SecureON {
    pub fn new(bytes: [u8; 6]) -> Self {
        Self { bytes }
    }

    pub fn to_string(&self) -> String {
        let bytes_iter = self.bytes.iter();
        let byte_str: Vec<String> = bytes_iter.map(|b| format!("{:x}", b)).collect();
        format!("{}", byte_str.join(""))
    }
}

#[derive(Debug)]
pub enum SecureONParseError {
    InvalidLength,
    InvalidBytes(String, usize),
}

impl FromStr for SecureON {
    type Err = SecureONParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes: [u8; 6] = [0x00; 6];

        if s.len() != 12 {
            return Err(SecureONParseError::InvalidLength);
        }

        for i in 0..(s.len() / 2) {
            let bytes_start = i * 2;
            let bytes_end = bytes_start + 2;
            match u8::from_str_radix(&s[bytes_start..bytes_end], 16) {
                Ok(hex) => bytes[i] = hex,
                Err(_) => {
                    let invalid_str = String::from(&s[bytes_start..bytes_end]);
                    let bad_octet = i + 1;
                    return Err(SecureONParseError::InvalidBytes(invalid_str, bad_octet))
                }
            }
        }

        Ok(SecureON { bytes })
    }
}

#[cfg(test)]
mod secureon_tests {
    use crate::SecureON;

    #[test]
    fn test_secureon_new() {
        let password = SecureON::new([0x97, 0x98, 0x99, 0xA0, 0xA1, 0xA2]);
        assert_eq!([0x97, 0x98, 0x99, 0xA0, 0xA1, 0xA2], password.bytes);
    }

    #[test]
    fn test_secureon_from_string() {
        let password: SecureON = "979899a0a1a2".parse().unwrap();
        assert_eq!([0x97, 0x98, 0x99, 0xA0, 0xA1, 0xA2], password.bytes);
    }
}
