//! Example for a client connection to a server.
//! This example connects to Google.com and then prints out the result
#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]
#![feature(impl_trait_in_assoc_type)]

#[doc(hidden)]
pub use esp_hal as hal;

use embassy_net::tcp::TcpSocket;
use embassy_net::{Config, Ipv4Address, Stack, StackResources};

use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use esp_backtrace as _;
use esp_mbedtls::X509;
use esp_mbedtls::{asynch::Session, set_debug, Certificates, Mode, TlsVersion};
use esp_println::logger::init_logger;
use esp_println::{print, println};
use esp_wifi::wifi::{
    ClientConfiguration, Configuration, WifiController, WifiDevice, WifiEvent, WifiStaDevice,
    WifiState,
};
use esp_wifi::{init, EspWifiInitFor};
use hal::{prelude::*, rng::Rng, timer::timg::TimerGroup};

// Patch until https://github.com/embassy-rs/static-cell/issues/16 is fixed
macro_rules! mk_static {
    ($t:ty,$val:expr) => {{
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        #[deny(unused_attributes)]
        let x = STATIC_CELL.uninit().write(($val));
        x
    }};
}

const SSID: &str = env!("SSID");
const PASSWORD: &str = env!("PASSWORD");

#[esp_hal_embassy::main]
async fn main(spawner: Spawner) -> ! {
    init_logger(log::LevelFilter::Info);

    let peripherals = esp_hal::init({
        let mut config = esp_hal::Config::default();
        config.cpu_clock = CpuClock::max();
        config
    });

    esp_alloc::heap_allocator!(115 * 1024);

    let timg0 = TimerGroup::new(peripherals.TIMG0);

    let init = init(
        EspWifiInitFor::Wifi,
        timg0.timer0,
        Rng::new(peripherals.RNG),
        peripherals.RADIO_CLK,
    )
    .unwrap();

    let wifi = peripherals.WIFI;
    let (wifi_interface, controller) =
        esp_wifi::wifi::new_with_mode(&init, wifi, WifiStaDevice).unwrap();

    cfg_if::cfg_if! {
        if #[cfg(feature = "esp32")] {
            let timg1 = TimerGroup::new(peripherals.TIMG1);
            esp_hal_embassy::init(timg1.timer0);
        } else {
            use esp_hal::timer::systimer::{SystemTimer, Target};
            let systimer = SystemTimer::new(peripherals.SYSTIMER).split::<Target>();
            esp_hal_embassy::init(systimer.alarm0);
        }
    }

    let config = Config::dhcpv4(Default::default());

    let seed = 1234; // very random, very secure seed

    // Init network stack
    let stack = &*mk_static!(
        Stack<WifiDevice<'_, WifiStaDevice>>,
        Stack::new(
            wifi_interface,
            config,
            mk_static!(StackResources<3>, StackResources::<3>::new()),
            seed
        )
    );

    spawner.spawn(connection(controller)).ok();
    spawner.spawn(net_task(&stack)).ok();

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

    let remote_endpoint = (Ipv4Address::new(142, 250, 185, 68), 443); // www.google.com
    println!("connecting...");
    let r = socket.connect(remote_endpoint).await;
    if let Err(e) = r {
        println!("connect error: {:?}", e);
        loop {}
    }

    set_debug(0);

    let tls = Session::new(
        &mut socket,
        "www.google.com",
        Mode::Client,
        TlsVersion::Tls1_3,
        Certificates {
            ca_chain: X509::pem(
                concat!(include_str!("./certs/www.google.com.pem"), "\0").as_bytes(),
            )
            .ok(),
            ..Default::default()
        },
        mk_static!([u8; 4096], [0; 4096]),
        mk_static!([u8; 4096], [0; 4096]),
    )
    .unwrap()
    .with_hardware_rsa(peripherals.RSA);

    println!("Start tls connect");
    let mut tls = tls.connect().await.unwrap();

    println!("connected!");
    let mut buf = [0; 1024];

    use embedded_io_async::Read;
    use embedded_io_async::Write;

    let r = tls
        .write_all(b"GET /notfound HTTP/1.0\r\nHost: www.google.com\r\n\r\n")
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
    println!();
    println!("Done");

    loop {}
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
                ssid: SSID.try_into().unwrap(),
                password: PASSWORD.try_into().unwrap(),
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
async fn net_task(stack: &'static Stack<WifiDevice<'static, WifiStaDevice>>) {
    stack.run().await
}
