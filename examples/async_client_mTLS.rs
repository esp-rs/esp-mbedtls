//! Example for a client connection using certificate authentication (mTLS)
#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]
#![allow(non_snake_case)]

#[doc(hidden)]
#[cfg(feature = "esp32")]
pub use esp32_hal as hal;
#[doc(hidden)]
#[cfg(feature = "esp32c3")]
pub use esp32c3_hal as hal;
#[doc(hidden)]
#[cfg(feature = "esp32s3")]
pub use esp32s3_hal as hal;

use embassy_executor::_export::StaticCell;
use embassy_net::tcp::TcpSocket;
use embassy_net::{Config, Ipv4Address, Stack, StackResources};

use embassy_executor::Executor;
use embassy_time::{Duration, Timer};
use embedded_svc::wifi::{ClientConfiguration, Configuration, Wifi};
use esp_backtrace as _;
use esp_mbedtls::{asynch::Session, set_debug, Mode, TlsVersion};
use esp_mbedtls::{Certificates, X509};
use esp_println::logger::init_logger;
use esp_println::{print, println};
use esp_wifi::wifi::{WifiController, WifiDevice, WifiEvent, WifiMode, WifiState};
use esp_wifi::{initialize, EspWifiInitFor};
use hal::clock::{ClockControl, CpuClock};
use hal::Rng;
use hal::{embassy, peripherals::Peripherals, prelude::*, timer::TimerGroup, Rtc};

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
    #[cfg(feature = "esp32")]
    let mut system = peripherals.DPORT.split();
    #[cfg(not(feature = "esp32"))]
    #[allow(unused_mut)]
    let mut system = peripherals.SYSTEM.split();
    #[cfg(feature = "esp32c3")]
    let clocks = ClockControl::configure(system.clock_control, CpuClock::Clock160MHz).freeze();
    #[cfg(any(feature = "esp32", feature = "esp32s3"))]
    let clocks = ClockControl::configure(system.clock_control, CpuClock::Clock240MHz).freeze();

    let mut rtc = Rtc::new(peripherals.RTC_CNTL);

    // Disable watchdog timers
    #[cfg(not(feature = "esp32"))]
    rtc.swd.disable();
    rtc.rwdt.disable();

    #[cfg(feature = "esp32c3")]
    let timer = hal::systimer::SystemTimer::new(peripherals.SYSTIMER).alarm0;
    #[cfg(any(feature = "esp32", feature = "esp32s3"))]
    let timer = hal::timer::TimerGroup::new(
        peripherals.TIMG1,
        &clocks,
        &mut system.peripheral_clock_control,
    )
    .timer0;
    let init = initialize(
        EspWifiInitFor::Wifi,
        timer,
        Rng::new(peripherals.RNG),
        system.radio_clock_control,
        &clocks,
    )
    .unwrap();

    let (wifi, _) = peripherals.RADIO.split();
    let (wifi_interface, controller) = esp_wifi::wifi::new_with_mode(&init, wifi, WifiMode::Sta);

    let timer_group0 = TimerGroup::new(
        peripherals.TIMG0,
        &clocks,
        &mut system.peripheral_clock_control,
    );
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
            break;
        }
        Timer::after(Duration::from_millis(500)).await;
    }

    let mut socket = TcpSocket::new(&stack, &mut rx_buffer, &mut tx_buffer);

    socket.set_timeout(Some(Duration::from_secs(10)));

    let remote_endpoint = (Ipv4Address::new(62, 210, 201, 125), 443); // certauth.cryptomix.com
    println!("connecting...");
    let r = socket.connect(remote_endpoint).await;
    if let Err(e) = r {
        println!("connect error: {:?}", e);
        loop {}
    }

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

    let tls: Session<_, 4096> = Session::new(
        &mut socket,
        "certauth.cryptomix.com",
        Mode::Client,
        TlsVersion::Tls1_3,
        certificates,
    )
    .unwrap();

    println!("Start tls connect");
    let mut tls = tls.connect().await.unwrap();

    println!("connected!");
    let mut buf = [0; 1024];

    use embedded_io::asynch::Read;
    use embedded_io::asynch::Write;

    let r = tls
        .write_all(b"GET /json/ HTTP/1.0\r\nHost: certauth.cryptomix.com\r\n\r\n")
        .await;
    if let Err(e) = r {
        println!("write error: {:?}", e);
        loop {}
    }

    loop {
        let n = match tls.read(&mut buf).await {
            Ok(n) => n,
            Err(esp_mbedtls::TlsError::Eof) => {
                break;
            }
            Err(e) => {
                println!("read error: {:?}", e);
                break;
            }
        };
        print!("{}", core::str::from_utf8(&buf[..n]).unwrap());
    }
    println!("Done");

    loop {}
}
