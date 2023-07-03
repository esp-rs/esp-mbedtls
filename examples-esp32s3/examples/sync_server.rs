#![no_std]
#![no_main]

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
    current_millis,
    wifi::{utils::create_network_interface, WifiMode},
    wifi_interface::WifiStack,
    EspWifiInitFor,
};
use hal::timer::TimerGroup;
use hal::{
    clock::{ClockControl, CpuClock},
    peripherals::Peripherals,
    prelude::*,
    Rng, Rtc,
};
use smoltcp::{iface::SocketStorage, wire::IpAddress};

const SSID: &str = env!("SSID");
const PASSWORD: &str = env!("PASSWORD");

#[entry]
fn main() -> ! {
    init_logger(log::LevelFilter::Info);

    let peripherals = Peripherals::take();
    let mut system = peripherals.SYSTEM.split();
    let clocks = ClockControl::configure(system.clock_control, CpuClock::Clock240MHz).freeze();

    let mut rtc = Rtc::new(peripherals.RTC_CNTL);

    // Disable watchdog timers
    rtc.rwdt.disable();

    let rngp = Rng::new(peripherals.RNG);
    let timer = TimerGroup::new(
        peripherals.TIMG1,
        &clocks,
        &mut system.peripheral_clock_control,
    );
    let init = esp_wifi::initialize(
        EspWifiInitFor::Wifi,
        timer.timer0,
        rngp,
        system.radio_clock_control,
        &clocks,
    )
    .unwrap();

    let (wifi, _) = peripherals.RADIO.split();
    let mut socket_set_entries: [SocketStorage; 3] = Default::default();
    let (iface, device, mut controller, sockets) =
        create_network_interface(&init, wifi, WifiMode::Sta, &mut socket_set_entries);
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

    println!(
        "Point your browser to http://{:?}/",
        wifi_stack.get_ip_info().unwrap().ip
    );
    let mut rx_buffer = [0u8; 1536];
    let mut tx_buffer = [0u8; 1536];
    let mut socket = wifi_stack.get_socket(&mut rx_buffer, &mut tx_buffer);

    // Dummy socket, while figuring out how to implement server
    let mut rx_buffer_dummy = [0u8; 1536];
    let mut tx_buffer_dummy = [0u8; 1536];
    let mut socket_dummy = wifi_stack.get_socket(&mut rx_buffer_dummy, &mut tx_buffer_dummy);
    let tls = Session::new(
        socket_dummy,
        "test.local",
        Mode::Server,
        TlsVersion::Tls1_2,
        Certificates {
            certs: X509::pem(include_bytes!("../certs/rootCA.crt")).ok(),
            client_cert: X509::pem(include_bytes!("../certs/server.crt")).ok(),
            client_key: X509::pem(include_bytes!("../certs/server.key")).ok(),
            ..Default::default()
        },
    )
    .unwrap();

    socket.listen(80).unwrap();
    set_debug(0);
    loop {
        socket.work();

        if !socket.is_open() {
            socket.listen(80).unwrap();
        }

        if socket.is_connected() {
            println!("New connection");

            let mut time_out = false;
            let wait_end = current_millis() + 20 * 1000;
            let mut buffer = [0u8; 1024];
            let mut pos = 0;

            loop {
                if let Ok(len) = socket.read(&mut buffer[pos..]) {
                    let to_print =
                        unsafe { core::str::from_utf8_unchecked(&buffer[..(pos + len)]) };

                    if to_print.contains("\r\n\r\n") {
                        print!("{}", to_print);
                        println!();
                        break;
                    }

                    pos += len;
                } else {
                    break;
                }

                if current_millis() > wait_end {
                    println!("Timed out");
                    time_out = true;
                    break;
                }
            }

            if !time_out {
                socket
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

                socket.flush().unwrap();
            }

            socket.close();

            println!("Done\n");
            println!();
        }

        // This seems to delay after a connection. Removed to allow instant connections
        //
        // let wait_end = current_millis() + 5 * 1000;
        // while current_millis() < wait_end {
        //     socket.work();
        // }
    }

}
