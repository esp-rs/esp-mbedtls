//! Example for a client connection to a server.
//! This example connects to either `Google.com` or `certauth.cryptomix.com` (mTLS) and then prints out the result.
//!
//! # mTLS
//! Use the mTLS feature to enable client authentication and send client certificates when doing a
//! request. Note that this will connect to `certauth.cryptomix.com` instead of `google.com`
#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]
#![feature(impl_trait_in_assoc_type)]

use core::ffi::CStr;

#[doc(hidden)]
pub use esp_hal as hal;

use embassy_net::tcp::TcpSocket;
use embassy_net::{Config, Ipv4Address, Runner, StackResources};

use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use esp_backtrace as _;
use esp_mbedtls::{asynch::Session, Certificates, Mode, TlsVersion};
use esp_mbedtls::{Tls, X509};
use esp_println::logger::init_logger;
use esp_println::{print, println};
use esp_wifi::wifi::{
    ClientConfiguration, Configuration, WifiController, WifiDevice, WifiEvent, WifiState,
};
use esp_wifi::{init, EspWifiController};
use hal::{clock::CpuClock, rng::Rng, timer::timg::TimerGroup};

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

// Setup configuration based on mTLS feature.
cfg_if::cfg_if! {
    if #[cfg(feature = "mtls")] {
        const REMOTE_IP: Ipv4Address = Ipv4Address::new(62, 210, 201, 125); // certauth.cryptomix.com
        const SERVERNAME: &CStr = c"certauth.cryptomix.com";
        const REQUEST: &[u8] = b"GET /json/ HTTP/1.0\r\nHost: certauth.cryptomix.com\r\n\r\n";
    } else {
        const REMOTE_IP: Ipv4Address = Ipv4Address::new(142, 250, 185, 68); // google.com
        const SERVERNAME: &CStr = c"www.google.com";
        const REQUEST: &[u8] = b"GET /notfound HTTP/1.0\r\nHost: www.google.com\r\n\r\n";
    }
}

esp_bootloader_esp_idf::esp_app_desc!();

#[esp_hal_embassy::main]
async fn main(spawner: Spawner) -> ! {
    init_logger(log::LevelFilter::Info);

    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    esp_alloc::heap_allocator!(size: 72 * 1024);
    esp_alloc::heap_allocator!(#[unsafe(link_section = ".dram2_uninit")] size: 64 * 1024);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let mut rng = Rng::new(peripherals.RNG);

    let esp_wifi_ctrl = &*mk_static!(
        EspWifiController<'_>,
        init(timg0.timer0, rng.clone(), peripherals.RADIO_CLK,).unwrap()
    );

    let (controller, interfaces) = esp_wifi::wifi::new(&esp_wifi_ctrl, peripherals.WIFI).unwrap();

    let wifi_interface = interfaces.sta;

    cfg_if::cfg_if! {
        if #[cfg(feature = "esp32")] {
            let timg1 = TimerGroup::new(peripherals.TIMG1);
            esp_hal_embassy::init(timg1.timer0);
        } else {
            use esp_hal::timer::systimer::SystemTimer;
            let systimer = SystemTimer::new(peripherals.SYSTIMER);
            esp_hal_embassy::init(systimer.alarm0);
        }
    }

    let config = Config::dhcpv4(Default::default());

    let seed = (rng.random() as u64) << 32 | rng.random() as u64;

    // Init network stack
    let (stack, runner) = embassy_net::new(
        wifi_interface,
        config,
        mk_static!(StackResources<3>, StackResources::<3>::new()),
        seed,
    );

    spawner.spawn(connection(controller)).ok();
    spawner.spawn(net_task(runner)).ok();

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

    let mut socket = TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);

    socket.set_timeout(Some(Duration::from_secs(10)));

    let remote_endpoint = (REMOTE_IP, 443);
    println!("connecting...");
    let r = socket.connect(remote_endpoint).await;
    if let Err(e) = r {
        println!("connect error: {:?}", e);
        #[allow(clippy::empty_loop)]
        loop {}
    }

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
    session.connect().await.unwrap();

    println!("connected!");
    let mut buf = [0; 1024];

    use embedded_io_async::Write;

    let r = session.write_all(REQUEST).await;
    if let Err(e) = r {
        println!("write error: {:?}", e);
        #[allow(clippy::empty_loop)]
        loop {}
    }

    loop {
        let n = match session.read(&mut buf).await {
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

    #[allow(clippy::empty_loop)]
    loop {}
}

#[embassy_executor::task]
async fn connection(mut controller: WifiController<'static>) {
    println!("start connection task");
    println!("Device capabilities: {:?}", controller.capabilities());
    #[cfg(feature = "esp32c6")]
    controller
        .set_power_saving(esp_wifi::config::PowerSaveMode::None)
        .unwrap();
    loop {
        if matches!(esp_wifi::wifi::wifi_state(), WifiState::StaConnected) {
            // wait until we're no longer connected
            controller.wait_for_event(WifiEvent::StaDisconnected).await;
            Timer::after(Duration::from_millis(5000)).await
        }
        if !matches!(controller.is_started(), Ok(true)) {
            let client_config = Configuration::Client(ClientConfiguration {
                ssid: SSID.try_into().unwrap(),
                password: PASSWORD.try_into().unwrap(),
                ..Default::default()
            });
            controller.set_configuration(&client_config).unwrap();
            println!("Starting wifi");
            controller.start_async().await.unwrap();
            println!("Wifi started!");
        }
        println!("About to connect...");

        match controller.connect_async().await {
            Ok(_) => println!("Wifi connected!"),
            Err(e) => {
                println!("Failed to connect to wifi: {e:?}");
                Timer::after(Duration::from_millis(5000)).await
            }
        }
    }
}

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, WifiDevice<'static>>) {
    runner.run().await
}
