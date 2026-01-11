//! Example of an HTTPS server.
//! Demonstrates the usage of the async API of esp-mbedtls.
//!
//! Since the server certificates are self-signed, the easiest way to test is with:
//! ```sh
//! curl -k https://<ip-printed-by-this-example>/
//! ```
//!
//! Alternatively, accept the self-signed certificate warning in the browser.

#![no_std]
#![no_main]

use embassy_executor::Spawner;

use embassy_net::IpListenEndpoint;
use embassy_net::Runner;
use embassy_net::StackResources;

use embassy_net::tcp::TcpSocket;
use embassy_time::Duration;
use embassy_time::Timer;

use esp_alloc::heap_allocator;

use esp_backtrace as _;

use esp_hal::ram;
use esp_hal::rng::Trng;
use esp_hal::rng::TrngSource;
use esp_hal::timer::timg::TimerGroup;

use esp_mbedtls::sys::accel::esp::EspAccel;
use esp_mbedtls::Tls;

use esp_metadata_generated::memory_range;

use esp_radio as _;
use esp_radio::wifi::sta::StationConfig;
use esp_radio::wifi::ModeConfig;
use esp_radio::wifi::WifiController;
use esp_radio::wifi::WifiDevice;
use esp_radio::wifi::WifiEvent;
use esp_radio::wifi::WifiStationState;

use log::{info, warn};

extern crate alloc;

#[path = "../../../common/server.rs"]
mod server;

macro_rules! mk_static {
    ($t:ty) => {{
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        STATIC_CELL.uninit()
    }};
    ($t:ty,$val:expr) => {{
        mk_static!($t).write($val)
    }};
}

const HEAP_SIZE: usize = 160 * 1024;

const RECLAIMED_RAM: usize =
    memory_range!("DRAM2_UNINIT").end - memory_range!("DRAM2_UNINIT").start;

esp_bootloader_esp_idf::esp_app_desc!();

const SSID: &str = env!("SSID");
const PASSWORD: &str = env!("PASSWORD");

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    esp_println::logger::init_logger(log::LevelFilter::Info);

    info!("Starting...");

    heap_allocator!(size: HEAP_SIZE - RECLAIMED_RAM);
    heap_allocator!(#[ram(reclaimed)] size: RECLAIMED_RAM);

    let peripherals = esp_hal::init(esp_hal::Config::default());

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(
        timg0.timer0,
        esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT)
            .software_interrupt0,
    );

    let mut accel = EspAccel::new(peripherals.SHA, peripherals.RSA);
    let _accel_queue = accel.start();

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);

    let trng = mk_static!(Trng, Trng::try_new().unwrap());

    // Configure and start the Wifi first
    let (controller, wifi_interfaces) =
        esp_radio::wifi::new(peripherals.WIFI, esp_radio::wifi::Config::default()).unwrap();
    let config = embassy_net::Config::dhcpv4(Default::default());

    let seed = (trng.random() as u64) << 32 | trng.random() as u64;

    // Init network stack
    let (stack, runner) = embassy_net::new(
        wifi_interfaces.station,
        config,
        mk_static!(StackResources<4>, StackResources::<4>::new()),
        seed,
    );

    spawner.spawn(connection(controller)).ok();
    spawner.spawn(net_task(runner)).ok();

    wait_ip(stack).await;

    let tls = mk_static!(Tls<'static>, Tls::new(trng).unwrap());

    tls.set_debug(4);

    spawner.spawn(http_task("Task 1", tls, stack)).ok();
    spawner.spawn(http_task("Task 2", tls, stack)).ok();

    // Don't exit so that the acceleration routines can stay registered
    core::future::pending::<()>().await
}

async fn wait_ip(stack: embassy_net::Stack<'_>) {
    loop {
        if stack.is_link_up() {
            break;
        }
        Timer::after(Duration::from_millis(500)).await;
    }

    info!("Waiting to get IP address...");
    loop {
        if let Some(config) = stack.config_v4() {
            info!("Got IP: {}", config.address);
            break;
        }
        Timer::after(Duration::from_millis(500)).await;
    }
}

#[embassy_executor::task]
async fn connection(mut controller: WifiController<'static>) {
    info!("Start connection task");
    info!("Device capabilities: {:?}", controller.capabilities());

    loop {
        if esp_radio::wifi::station_state() == WifiStationState::Connected {
            // wait until we're no longer connected
            controller
                .wait_for_event(WifiEvent::StationDisconnected)
                .await;
            Timer::after(Duration::from_millis(5000)).await
        }
        if !matches!(controller.is_started(), Ok(true)) {
            let client_config = ModeConfig::Station(
                StationConfig::default()
                    .with_ssid(SSID.into())
                    .with_password(PASSWORD.into()),
            );
            controller.set_config(&client_config).unwrap();
            info!("Starting wifi");
            controller.start_async().await.unwrap();
            info!("Wifi started!");
        }

        info!("About to connect...");

        match controller.connect_async().await {
            Ok(_) => info!("Wifi connected!"),
            Err(e) => {
                info!("Failed to connect to wifi: {e:?}");
                Timer::after(Duration::from_millis(5000)).await
            }
        }
    }
}

#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, WifiDevice<'static>>) {
    runner.run().await
}

#[embassy_executor::task(pool_size = 2)]
async fn http_task(
    task_id: &'static str,
    tls: &'static Tls<'static>,
    stack: embassy_net::Stack<'static>,
) {
    loop {
        let mut rx_buf = [0; 1024];
        let mut tx_buf = [0; 1024];

        let mut socket = TcpSocket::new(stack, &mut rx_buf, &mut tx_buf);

        info!("[{}] Listening on port 443", task_id);

        socket
            .accept(IpListenEndpoint {
                addr: None,
                port: 443,
            })
            .await
            .unwrap();

        info!(
            "[{}] Accepted connection from: {:?}",
            task_id,
            socket.remote_endpoint()
        );

        let mut buf = [0u8; 4096];

        if let Err(e) = server::reply(tls.reference(), &mut socket, false, &mut buf).await {
            warn!(
                "[{}] Error handling connection from {:?}: {:?}",
                task_id,
                socket.remote_endpoint(),
                e
            );
        } else {
            info!(
                "[{}] Connection from {:?} handled successfully",
                task_id,
                socket.remote_endpoint()
            );
        }

        socket.close();
    }
}
