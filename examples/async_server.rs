//! Example for an async server.
//! Contains a basic server implementation to test mbedtls in server mode.
//!
//! This example uses self-signed certificate. Your browser may display an error.
//! You have to enable the exception to then proceed, of if using curl, use the flag `-k`.
#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

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

use embassy_executor::_export::StaticCell;
use embassy_net::tcp::TcpSocket;
use embassy_net::{Config, Stack, StackResources};

use embassy_executor::Executor;
use embassy_time::{Duration, Timer};
use embedded_svc::wifi::{ClientConfiguration, Configuration, Wifi};
use esp_backtrace as _;
use esp_mbedtls::{asynch::Session, set_debug, Certificates, Mode, TlsVersion};
use esp_mbedtls::{TlsError, X509};
use esp_println::logger::init_logger;
use esp_println::{print, println};
use esp_wifi::wifi::{WifiController, WifiDevice, WifiEvent, WifiMode, WifiState};
use esp_wifi::{initialize, EspWifiInitFor};
use hal::clock::ClockControl;
use hal::Rng;
use hal::{embassy, peripherals::Peripherals, prelude::*, timer::TimerGroup};
use smoltcp::wire::IpListenEndpoint;

const SSID: &str = env!("SSID");
const PASSWORD: &str = env!("PASSWORD");

macro_rules! singleton {
    ($val:expr) => {{
        type T = impl Sized;
        static STATIC_CELL: StaticCell<T> = StaticCell::new();
        let (x,) = STATIC_CELL.init(($val,));
        x
    }};
}

static EXECUTOR: StaticCell<Executor> = StaticCell::new();

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
    let (wifi_interface, controller) =
        esp_wifi::wifi::new_with_mode(&init, wifi, WifiMode::Sta).unwrap();

    let timer_group0 = TimerGroup::new(peripherals.TIMG0, &clocks);
    embassy::init(&clocks, timer_group0.timer0);

    let config = Config::dhcpv4(Default::default());

    let seed = 1234; // very random, very secure seed

    // Init network stack
    let stack = &*singleton!(Stack::new(
        wifi_interface,
        config,
        singleton!(StackResources::<3>::new()),
        seed
    ));

    let executor = EXECUTOR.init(Executor::new());
    executor.run(|spawner| {
        spawner.spawn(connection(controller)).ok();
        spawner.spawn(net_task(&stack)).ok();
        spawner.spawn(task(&stack)).ok();
    });
}

#[embassy_executor::task]
async fn connection(mut controller: WifiController<'static>) {
    println!("start connection task");
    println!("Device capabilities: {:?}", controller.get_capabilities());
    loop {
        match esp_wifi::wifi::get_wifi_state() {
            WifiState::StaConnected => {
                // wait until we're no longer connected
                controller.wait_for_event(WifiEvent::StaDisconnected).await;
                Timer::after(Duration::from_millis(5000)).await
            }
            _ => {}
        }
        if !matches!(controller.is_started(), Ok(true)) {
            let client_config = Configuration::Client(ClientConfiguration {
                ssid: SSID.into(),
                password: PASSWORD.into(),
                ..Default::default()
            });
            controller.set_configuration(&client_config).unwrap();
            println!("Starting wifi");
            controller.start().await.unwrap();
            println!("Wifi started!");
        }
        println!("About to connect...");

        match controller.connect().await {
            Ok(_) => println!("Wifi connected!"),
            Err(e) => {
                println!("Failed to connect to wifi: {e:?}");
                Timer::after(Duration::from_millis(5000)).await
            }
        }
    }
}

#[embassy_executor::task]
async fn net_task(stack: &'static Stack<WifiDevice<'static>>) {
    stack.run().await
}

#[embassy_executor::task]
async fn task(stack: &'static Stack<WifiDevice<'static>>) {
    let mut rx_buffer = [0; 4096];
    let mut tx_buffer = [0; 4096];

    loop {
        if stack.is_link_up() {
            break;
        }
        Timer::after(Duration::from_millis(500)).await;
    }

    println!("Waiting to get IP address...");
    loop {
        if let Some(config) = stack.config_v4() {
            println!("Got IP: {}", config.address);
            println!(
                "Point your browser to https://{}/",
                config.address.address()
            );
            break;
        }
        Timer::after(Duration::from_millis(500)).await;
    }

    let mut socket = TcpSocket::new(&stack, &mut rx_buffer, &mut tx_buffer);
    socket.set_timeout(Some(Duration::from_secs(10)));
    loop {
        println!("Waiting for connection...");
        let r = socket
            .accept(IpListenEndpoint {
                addr: None,
                port: 443,
            })
            .await;
        println!("Connected...");

        if let Err(e) = r {
            println!("connect error: {:?}", e);
            continue;
        }

        set_debug(0);
        use embedded_io::asynch::Read;
        use embedded_io::asynch::Write;

        let mut buffer = [0u8; 1024];
        let mut pos = 0;
        let tls: Session<_, 4096> = Session::new(
            &mut socket,
            "",
            Mode::Server,
            TlsVersion::Tls1_2,
            Certificates {
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
        )
        .unwrap();

        println!("Start tls connect");
        match tls.connect().await {
            Ok(mut connected_session) => {
                log::info!("Got session");
                loop {
                    match connected_session.read(&mut buffer).await {
                        Ok(0) => {
                            println!("read EOF");
                            break;
                        }
                        Ok(len) => {
                            let to_print =
                                unsafe { core::str::from_utf8_unchecked(&buffer[..(pos + len)]) };

                            if to_print.contains("\r\n\r\n") {
                                print!("{}", to_print);
                                println!();
                                break;
                            }

                            pos += len;
                        }
                        Err(e) => {
                            println!("read error: {:?}", e);
                            break;
                        }
                    };
                }

                let r = connected_session
                    .write_all(
                        b"HTTP/1.0 200 OK\r\n\r\n\
                            <html>\
                                <body>\
                                    <h1>Hello Rust! Hello esp-mbedtls!</h1>\
                                </body>\
                            </html>\r\n\
                            ",
                    )
                    .await;
                if let Err(e) = r {
                    println!("write error: {:?}", e);
                }

                Timer::after(Duration::from_millis(1000)).await;

                drop(connected_session);
            }
            Err(TlsError::MbedTlsError(-30592)) => {
                println!("Fatal message: Please enable the exception for a self-signed certificate in your browser");
            }
            Err(error) => {
                panic!("{:?}", error);
            }
        }
        println!("Closing socket");
        socket.close();
        Timer::after(Duration::from_millis(1000)).await;

        socket.abort();
    }
}
