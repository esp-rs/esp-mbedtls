//! Example for a sync server.
//! Contains a basic server implementation to test mbedtls in server mode.
//!
//! This example uses self-signed certificate. Your browser may display an error.
//! You have to enable the exception to then proceed, of if using curl, use the flag `-k`.
#![no_std]
#![no_main]

use embedded_io::blocking::*;
use embedded_svc::{
    ipv4::Interface,
    wifi::{ClientConfiguration, Configuration, Wifi},
};
use esp_backtrace as _;
use esp_mbedtls::{set_debug, Mode, TlsError, TlsVersion};
use esp_mbedtls::{Certificates, Session, X509};
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
use smoltcp::iface::SocketStorage;

const SSID: &str = env!("SSID");
const PASSWORD: &str = env!("PASSWORD");

#[entry]
fn main() -> ! {
    init_logger(log::LevelFilter::Info);

    let peripherals = Peripherals::take();
    let mut system = peripherals.DPORT.split();
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
        "Point your browser to https://{:?}/",
        wifi_stack.get_ip_info().unwrap().ip
    );
    let mut rx_buffer = [0u8; 1536];
    let mut tx_buffer = [0u8; 1536];
    let mut socket = wifi_stack.get_socket(&mut rx_buffer, &mut tx_buffer);

    socket.listen(443).unwrap();
    set_debug(0);
    loop {
        socket.work();

        if !socket.is_open() {
            socket.listen(443).unwrap();
        }

        if socket.is_connected() {
            println!("New connection");

            let mut time_out = false;
            let wait_end = current_millis() + 20 * 1000;
            let mut buffer = [0u8; 1024];
            let mut pos = 0;

            let tls = Session::new(
                &mut socket,
                "",
                Mode::Server,
                TlsVersion::Tls1_2,
                Certificates {
                    // Use self-signed certificates
                    certificate: X509::pem(CERT.as_bytes()).ok(),
                    private_key: X509::pem(PRIVATE_KEY.as_bytes()).ok(),
                    ..Default::default()
                },
            )
            .unwrap();
            match tls.connect() {
                Ok(mut connected_session) => {
                    loop {
                        if let Ok(len) = connected_session.read(&mut buffer[pos..]) {
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
                        connected_session
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

                    drop(connected_session);
                }
                Err(TlsError::MbedTlsError(-30592)) => {
                    println!("Fatal message: Please enable the exception for a self-signed certificate in your browser");
                }
                Err(error) => {
                    panic!("{:?}", error);
                }
            }

            socket.close();

            println!("Done\n");
            println!();
        }
    }
}

// Self-signed certificates
static CERT: &str = "
-----BEGIN CERTIFICATE-----
MIIDHzCCAgegAwIBAgIUWV06V4OAM8QHlylNMK/byYU86w4wDQYJKoZIhvcNAQEL
BQAwHzELMAkGA1UEBhMCQ0ExEDAOBgNVBAgMB09udGFyaW8wHhcNMjMwNzA0MjAx
MjMxWhcNMjQwNzAzMjAxMjMxWjAfMQswCQYDVQQGEwJDQTEQMA4GA1UECAwHT250
YXJpbzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALOZODOA/LXASGMj
jzTUKMC7iHsi1/OsAS1un8BhFd3UPuDR17k334nErGoWL40Oy44PZ1r87nMR/IKf
J4qCsCKjAtDQDoBs+9/p0VSI0QevUvbEYGpEDodKXRu/PBuS6z3dsxTuoQ7KUBTd
BwZjCf3SMgJ4Uz9cptDdZNlc2h9RTebJtw8EyrobZQ5ExYdP8BZVJkTkomxWZlNc
OFjPeyeMnJCKP2Dw9DK4ObYC3aawCh2TMvmv2K0yibYyh4CmAwfs/x+yIQaYmyow
grbS1O6QJS4t7NU5SPhDywBlNKHZrECLYQC8Omzbp0X4oI2K/ehAJGy0JIC7jPGe
D9l2E10CAwEAAaNTMFEwHQYDVR0OBBYEFPHfThLZHfB42pOcZ0dMsh26GifzMB8G
A1UdIwQYMBaAFPHfThLZHfB42pOcZ0dMsh26GifzMA8GA1UdEwEB/wQFMAMBAf8w
DQYJKoZIhvcNAQELBQADggEBAHdebHonjUEd36nJMI/xf2WHd9Dd1paU6HV7rB/t
qSBXaYZcn3fA7BhH3D02i5z3b5g+Co21uF2LaKycYsD42hFOY4YYf7WP/bkkHyHL
j7rlKkj/qQPOPa8yfTyWvdfnECPdGM/YyZE0CYr7nt3DKD7c+bgFwjH2JaoOJdPa
HBNoqbEWFH7ftEzDykBQULbbl6aDusMIQca2sLrQ5BvQwaEMJ5A6KVMvmt3kjkmN
Tw4Jhadscao8G9MtpPQjAbBoJlA9fYoZEWdOuieruAMjEyLJwBQVjAxdgWAyH1wZ
hJBECkdIk2jMh4RNCnp2vHmiYIFIMIasUHWPqZGNLdgwZs4=
-----END CERTIFICATE-----
\0";

static PRIVATE_KEY: &str = "
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCzmTgzgPy1wEhj
I4801CjAu4h7ItfzrAEtbp/AYRXd1D7g0de5N9+JxKxqFi+NDsuOD2da/O5zEfyC
nyeKgrAiowLQ0A6AbPvf6dFUiNEHr1L2xGBqRA6HSl0bvzwbkus93bMU7qEOylAU
3QcGYwn90jICeFM/XKbQ3WTZXNofUU3mybcPBMq6G2UORMWHT/AWVSZE5KJsVmZT
XDhYz3snjJyQij9g8PQyuDm2At2msAodkzL5r9itMom2MoeApgMH7P8fsiEGmJsq
MIK20tTukCUuLezVOUj4Q8sAZTSh2axAi2EAvDps26dF+KCNiv3oQCRstCSAu4zx
ng/ZdhNdAgMBAAECggEAURa+71Ivx4gXpttpTzrzY4HIr4Ad7OEebvrhmiS7kLrB
4RQdyHzXqwZnqkZ2FcQ2V9/QlJ5asw3N6tQdMEatbBYZsVofEhEi8AhMAVT8u/GH
De/AcHpl7OPAgkSnyPNez0IIF01e3qSt352kDFgvLLD473CQda1JjEhJvnJT8Ysr
210UoErit/LWr1nY0U0obX7+TVFjNy9d3Yu48VQOf0SxlVIDHuDTKxwRTJ21Y9UA
3GQ86CW8CP8mjluEKQff4N4HAEapGKixs93tS84BDUWO1Tex55ewvhX7FaVagSUB
aHDmuwmpKR20ZqGGCX66nsKjYNbj3F/AWvbfbNMU6QKBgQDoE6SIVMO69B1dndg4
FkpBtFwmMJrxaJiSMm/m1O5yFO5UuT2cRtGSIZn1tyQ79B8Ml7w3vAkTEzmqI9HB
Q656fGI364vRRaJRlLK++Qw+CrwwnIhH2xChy5LhsdXx1QPKYqYTG8zLtxtK9mIJ
TLfciLDCAVTrZGvxqn+WFtK7+wKBgQDGHLXI9LVY6BVUtp5HwHYM1bxWVS1lbfXh
uJJJM1dxPlVBBgEJLtFPlnIPqjs0EZvv7YK9DMyT4hlEyDmLLYPRw/xba3iBxAbK
oD1em1TL6b2HkdmhdBj5NfEl1iSsGk5OsOelub5Fw5Ygt0lg4MBE2WFxgyTnysyZ
IENLGKo2hwKBgEFQJeHoWR1oTktmfM9sFoHfTH/C9hgyo52hbDS+gEzC70AQ0fIF
TD2gD0BDxoLI9WQJ4AKffL5NjtD/O6z0a0o1bz7ln3fJ7SCghJ2SYYukYcocg44V
bNzb+f5imh9xH5v5n1uJW12JrriuFnEfki8SmQxAa7HDlU1x+m43Bh+5AoGANR8b
q2/adKV+msGA/ZJg1R42qxuZ2Zm7lbPtHc2zg70IFTBr9K9mFqYrnYGy8EpMevA/
3ztgW8MDrYrWyzgAIa4gq87MeFc8zvZanlSeTzM0y/ZS2dUMoT5SlCewm6lOGBGd
e7WrjH9ecRVUirKZO5ziYRKeQb0CUYjyIl/RvF8CgYEAu8pve6R4EzNLCJ1UnNpZ
vfTiJZbxq9K9AaSKGyRV6I9C+dX8of2Q8FdXjWiavOs1NHPJn3llgZhthc13BkOz
p1kFPp1tYHDG+i5qognKHG8czCabuzdalket/vqkBYFsQcebRULAe3c/OZzEQ5J3
7aA6cUR9TA8wcvg4KrpoMqg=
-----END PRIVATE KEY-----
\0";
