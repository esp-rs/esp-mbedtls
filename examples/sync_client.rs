//! Example for a client connection to a server.
//! This example connects to either `Google.com` or `certauth.cryptomix.com` (mTLS) and then prints out the result.
//!
//! # mTLS
//! Use the mTLS feature to enable client authentication and send client certificates when doing a
//! request. Note that this will connect to `certauth.cryptomix.com` instead of `google.com`
#![no_std]
#![no_main]

use core::ffi::CStr;

#[doc(hidden)]
pub use esp_hal as hal;

use blocking_network_stack::Stack;

use esp_alloc as _;
use esp_backtrace as _;
use esp_mbedtls::{Certificates, Session};
use esp_mbedtls::{Mode, Tls, TlsVersion, X509};
use esp_println::{logger::init_logger, print, println};
use esp_wifi::{
    init,
    wifi::{ClientConfiguration, Configuration},
};
use hal::{clock::CpuClock, main, rng::Rng, time, timer::timg::TimerGroup};
use smoltcp::{
    iface::{SocketSet, SocketStorage},
    wire::{DhcpOption, IpAddress},
};

const SSID: &str = env!("SSID");
const PASSWORD: &str = env!("PASSWORD");

// Setup configuration based on mTLS feature.
cfg_if::cfg_if! {
    if #[cfg(feature = "mtls")] {
        const REMOTE_IP: IpAddress = IpAddress::v4(62, 210, 201, 125); // certauth.cryptomix.com
        const SERVERNAME: &CStr = c"certauth.cryptomix.com";
        const REQUEST: &[u8] = b"GET /json/ HTTP/1.0\r\nHost: certauth.cryptomix.com\r\n\r\n";
    } else {
        const REMOTE_IP: IpAddress = IpAddress::v4(142, 250, 185, 68); // google.com
        const SERVERNAME: &CStr = c"www.google.com";
        const REQUEST: &[u8] = b"GET /notfound HTTP/1.0\r\nHost: www.google.com\r\n\r\n";
    }
}

esp_bootloader_esp_idf::esp_app_desc!();

#[main]
fn main() -> ! {
    init_logger(log::LevelFilter::Info);
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    esp_alloc::heap_allocator!(size: 72 * 1024);
    esp_alloc::heap_allocator!(#[unsafe(link_section = ".dram2_uninit")] size: 64 * 1024);

    let timg0 = TimerGroup::new(peripherals.TIMG0);

    let mut rng = Rng::new(peripherals.RNG);

    let esp_wifi_ctrl = init(timg0.timer0, rng.clone(), peripherals.RADIO_CLK).unwrap();

    let (mut controller, interfaces) =
        esp_wifi::wifi::new(&esp_wifi_ctrl, peripherals.WIFI).unwrap();

    let mut device = interfaces.sta;
    let iface = create_interface(&mut device);

    let mut socket_set_entries: [SocketStorage; 3] = Default::default();
    let mut sockets = SocketSet::new(&mut socket_set_entries[..]);
    let mut dhcp_socket = smoltcp::socket::dhcpv4::Socket::new();
    // we can set a hostname here (or add other DHCP options)
    dhcp_socket.set_outgoing_options(&[DhcpOption {
        kind: 12,
        data: b"esp-mbedtls",
    }]);
    sockets.add(dhcp_socket);

    let now = || time::Instant::now().duration_since_epoch().as_millis();
    let wifi_stack = Stack::new(iface, device, sockets, now, rng.random());

    controller
        .set_power_saving(esp_wifi::config::PowerSaveMode::None)
        .unwrap();

    println!("Call wifi_connect");
    let client_config = Configuration::Client(ClientConfiguration {
        ssid: SSID.try_into().unwrap(),
        password: PASSWORD.try_into().unwrap(),
        ..Default::default()
    });
    #[cfg(feature = "esp32c6")]
    controller
        .set_power_saving(esp_wifi::config::PowerSaveMode::None)
        .unwrap();
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
                #[allow(clippy::empty_loop)]
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

    socket.open(REMOTE_IP, 443).unwrap();

    cfg_if::cfg_if! {
        if #[cfg(feature = "mtls")] {
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
        } else {
            let certificates = Certificates {
                ca_chain: X509::pem(
                    concat!(include_str!("./certs/www.google.com.pem"), "\0").as_bytes(),
                )
                .ok(),
                ..Default::default()
            };
        }
    }

    let mut tls = Tls::new(peripherals.SHA)
        .unwrap()
        .with_hardware_rsa(peripherals.RSA);

    tls.set_debug(0);

    let mut session = Session::new(
        &mut socket,
        Mode::Client {
            servername: SERVERNAME,
        },
        TlsVersion::Tls1_3,
        certificates,
        tls.reference(),
    )
    .unwrap();

    println!("Start tls connect");
    session.connect().unwrap();

    println!("Write to connection");
    session.write(REQUEST).unwrap();

    println!("Read from connection");
    let mut buffer = [0u8; 4096];
    loop {
        match session.read(&mut buffer) {
            Ok(len) => {
                print!("{}", unsafe {
                    core::str::from_utf8_unchecked(&buffer[..len])
                });
            }
            Err(_) => {
                println!();
                break;
            }
        }
    }
    println!("Done");

    #[allow(clippy::empty_loop)]
    loop {}
}

// some smoltcp boilerplate
fn timestamp() -> smoltcp::time::Instant {
    smoltcp::time::Instant::from_micros(
        esp_hal::time::Instant::now()
            .duration_since_epoch()
            .as_micros() as i64,
    )
}

fn create_interface(device: &mut esp_wifi::wifi::WifiDevice) -> smoltcp::iface::Interface {
    // users could create multiple instances but since they only have one WifiDevice
    // they probably can't do anything bad with that
    smoltcp::iface::Interface::new(
        smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ethernet(
            smoltcp::wire::EthernetAddress::from_bytes(&device.mac_address()),
        )),
        device,
        timestamp(),
    )
}
