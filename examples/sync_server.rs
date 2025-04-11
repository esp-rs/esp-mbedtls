//! Example for a sync server.
//! Contains a basic server implementation to test mbedtls in server mode.
//!
//! This example uses self-signed certificate. Your browser may display an error.
//! You have to enable the exception to then proceed, of if using curl, use the flag `-k`.
//!
//! # mTLS
//! Running this example with the feature `mtls` will make the server request a client
//! certificate for the connection. If you send a request, without passing
//! certificates, you will get an error. Theses certificates below are generated
//! to work is the configured CA:
//!
//! certificate.pem
//! ```text
#![doc = include_str!("./certs/certificate.pem")]
//! ```
//!
//! private_key.pem
//! ```text
#![doc = include_str!("./certs/private_key.pem")]
//! ```
//!
//! Test with curl:
//! ```bash
//! curl https://<IP>/ --cert certificate.pem --key private_key.pem -k
//! ```
//!
#![no_std]
#![no_main]

#[doc(hidden)]
pub use esp_hal as hal;

use blocking_network_stack::Stack;

use embedded_io::*;
use esp_backtrace as _;
use esp_mbedtls::{Certificates, Session};
use esp_mbedtls::{Mode, Tls, TlsError, TlsVersion, X509};
use esp_println::{logger::init_logger, print, println};
use esp_wifi::{
    init,
    wifi::{ClientConfiguration, Configuration},
};
use hal::{clock::CpuClock, main, rng::Rng, time, timer::timg::TimerGroup};
use smoltcp::{
    iface::{SocketSet, SocketStorage},
    wire::DhcpOption,
};

const SSID: &str = env!("SSID");
const PASSWORD: &str = env!("PASSWORD");

#[main]
fn main() -> ! {
    init_logger(log::LevelFilter::Info);
    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    esp_alloc::heap_allocator!(size: 115 * 1024);

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

    println!(
        "Point your browser to https://{:?}/",
        wifi_stack.get_ip_info().unwrap().ip
    );
    let mut rx_buffer = [0u8; 1536];
    let mut tx_buffer = [0u8; 1536];
    let mut socket = wifi_stack.get_socket(&mut rx_buffer, &mut tx_buffer);

    socket.listen(443).unwrap();

    let mut tls = Tls::new(peripherals.SHA)
        .unwrap()
        .with_hardware_rsa(peripherals.RSA);

    tls.set_debug(0);

    loop {
        socket.work();

        if !socket.is_open() {
            socket.listen(443).unwrap();
        }

        if socket.is_connected() {
            println!("New connection");

            let mut time_out = false;
            let wait_end = now() + 20 * 1000;
            let mut buffer = [0u8; 1024];
            let mut pos = 0;

            let mut session = Session::new(
                &mut socket,
                Mode::Server,
                TlsVersion::Tls1_2,
                Certificates {
                    // Provide a ca_chain if you want to enable mTLS for the server.
                    #[cfg(feature = "mtls")]
                    ca_chain: X509::pem(
                        concat!(include_str!("./certs/ca_cert.pem"), "\0").as_bytes(),
                    )
                    .ok(),
                    // Use self-signed certificates
                    certificate: X509::pem(
                        concat!(include_str!("./certs/certificate.pem"), "\0").as_bytes(),
                    )
                    .ok(),
                    private_key: X509::pem(
                        concat!(include_str!("./certs/private_key.pem"), "\0").as_bytes(),
                    )
                    .ok(),
                    ..Default::default()
                },
                tls.reference(),
            )
            .unwrap();

            match session.connect() {
                Ok(_) => {
                    while let Ok(len) = session.read(&mut buffer[pos..]) {
                        let to_print =
                            unsafe { core::str::from_utf8_unchecked(&buffer[..(pos + len)]) };

                        if to_print.contains("\r\n\r\n") {
                            print!("{}", to_print);
                            println!();
                            break;
                        }

                        pos += len;

                        if now() > wait_end {
                            println!("Timed out");
                            time_out = true;
                            break;
                        }
                    }

                    if !time_out {
                        session
                            .write_all(
                                b"HTTP/1.0 200 OK\r\n\r\n\
                                    <html>\
                                    <body>\
                                    <h1>Hello Rust! Hello esp-mbedtls!</h1>\
                                    </body>\
                                    </html>\r\n\
                                    ",
                            )
                            .unwrap();
                    }
                }
                Err(TlsError::NoClientCertificate) => {
                    println!("Error: No client certificates given. Please provide client certificates during your request");
                }
                Err(TlsError::MbedTlsError(-30592)) => {
                    println!("Fatal message: Please enable the exception for a self-signed certificate in your browser");
                }
                Err(error) => {
                    panic!("{:?}", error);
                }
            }

            drop(session);
            socket.close();

            println!("Done\n");
            println!();
        }
    }
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
