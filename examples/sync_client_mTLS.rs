//! Example for a client connection using certificate authentication (mTLS)
#![no_std]
#![no_main]
#![allow(non_snake_case)]

#[doc(hidden)]
#[cfg(feature = "esp32")]
pub use esp32_hal as hal;
#[doc(hidden)]
#[cfg(feature = "esp32c3")]
pub use esp32c3_hal as hal;
#[doc(hidden)]
#[cfg(feature = "esp32s2")]
pub use esp32s2_hal as hal;
#[doc(hidden)]
#[cfg(feature = "esp32s3")]
pub use esp32s3_hal as hal;

use embedded_io::blocking::*;
use embedded_svc::{
    ipv4::Interface,
    wifi::{ClientConfiguration, Configuration, Wifi},
};
use esp_backtrace as _;
use esp_mbedtls::{set_debug, Mode, TlsVersion, X509};
use esp_mbedtls::{Certificates, Session};
use esp_println::{logger::init_logger, print, println};
use esp_wifi::{
    current_millis, initialize,
    wifi::{utils::create_network_interface, WifiMode},
    wifi_interface::WifiStack,
    EspWifiInitFor,
};
use hal::{clock::ClockControl, peripherals::Peripherals, prelude::*, Rng};
use smoltcp::{iface::SocketStorage, wire::IpAddress};

const SSID: &str = env!("SSID");
const PASSWORD: &str = env!("PASSWORD");

#[entry]
fn main() -> ! {
    init_logger(log::LevelFilter::Info);

    let peripherals = Peripherals::take();
    let system = peripherals.SYSTEM.split();
    let clocks = ClockControl::max(system.clock_control).freeze();

    #[cfg(feature = "esp32c3")]
    let timer = hal::systimer::SystemTimer::new(peripherals.SYSTIMER).alarm0;
    #[cfg(any(feature = "esp32", feature = "esp32s2", feature = "esp32s3"))]
    let timer = hal::timer::TimerGroup::new(peripherals.TIMG1, &clocks).timer0;
    let init = initialize(
        EspWifiInitFor::Wifi,
        timer,
        Rng::new(peripherals.RNG),
        system.radio_clock_control,
        &clocks,
    )
    .unwrap();

    #[cfg(feature = "esp32s2")]
    let wifi = peripherals.RADIO.split();
    #[cfg(not(feature = "esp32s2"))]
    let (wifi, _) = peripherals.RADIO.split();
    let mut socket_set_entries: [SocketStorage; 3] = Default::default();
    let (iface, device, mut controller, sockets) =
        create_network_interface(&init, wifi, WifiMode::Sta, &mut socket_set_entries).unwrap();
    let wifi_stack = WifiStack::new(iface, device, sockets, current_millis);

    println!("Call wifi_connect");
    let client_config = Configuration::Client(ClientConfiguration {
        ssid: SSID.into(),
        password: PASSWORD.into(),
        ..Default::default()
    });
    controller.set_configuration(&client_config).unwrap();
    controller.start().unwrap();
    controller.connect().unwrap();

    println!("Wait to get connected");
    loop {
        let res = controller.is_connected();
        match res {
            Ok(connected) => {
                if connected {
                    break;
                }
            }
            Err(err) => {
                println!("{:?}", err);
                loop {}
            }
        }
    }

    // wait for getting an ip address
    println!("Wait to get an ip address");
    loop {
        wifi_stack.work();

        if wifi_stack.is_iface_up() {
            println!("Got ip {:?}", wifi_stack.get_ip_info());
            break;
        }
    }

    println!("We are connected!");

    println!("Making HTTP request");
    let mut rx_buffer = [0u8; 1536];
    let mut tx_buffer = [0u8; 1536];
    let mut socket = wifi_stack.get_socket(&mut rx_buffer, &mut tx_buffer);

    socket.work();

    socket
        .open(IpAddress::v4(62, 210, 201, 125), 443) // certauth.cryptomix.com
        .unwrap();

    set_debug(0);

    let certificates = Certificates {
        ca_chain: X509::pem(
            concat!(include_str!("./certs/certauth.cryptomix.com.pem"), "\0").as_bytes(),
        )
        .ok(),
        certificate: X509::pem(concat!(include_str!("./certs/certificate.pem"), "\0").as_bytes())
            .ok(),
        private_key: X509::pem(concat!(include_str!("./certs/private_key.pem"), "\0").as_bytes())
            .ok(),
        password: None,
    };

    let tls = Session::new(
        &mut socket,
        "certauth.cryptomix.com",
        Mode::Client,
        TlsVersion::Tls1_3,
        certificates,
    )
    .unwrap();

    println!("Start tls connect");
    let mut tls = tls.connect().unwrap();

    println!("Write to connection");
    tls.write(b"GET /json/ HTTP/1.0\r\nHost: certauth.cryptomix.com\r\n\r\n")
        .unwrap();

    println!("Read from connection");
    let mut buffer = [0u8; 4096];
    loop {
        match tls.read(&mut buffer) {
            Ok(len) => {
                print!("{}", unsafe {
                    core::str::from_utf8_unchecked(&buffer[..len as usize])
                });
            }
            Err(_) => {
                println!();
                break;
            }
        }
    }
    println!("Done");

    loop {}
}
