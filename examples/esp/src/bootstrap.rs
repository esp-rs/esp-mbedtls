//! An `esp-hal` bootstrapping code shared by all network examples

use embassy_executor::Spawner;

use embassy_net::{Runner, Stack, StackResources};

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

use log::info;

extern crate alloc;

#[macro_export]
macro_rules! mk_static {
    ($t:ty) => {{
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        STATIC_CELL.uninit()
    }};
    ($t:ty,$val:expr) => {{
        mk_static!($t).write($val)
    }};
}

pub const RECLAIMED_RAM: usize =
    memory_range!("DRAM2_UNINIT").end - memory_range!("DRAM2_UNINIT").start;

esp_bootloader_esp_idf::esp_app_desc!();

const SSID: &str = env!("SSID");
const PASSWORD: &str = env!("PASSWORD");

pub async fn bootstrap_stack<const SOCKETS: usize>(
    spawner: Spawner,
    stack_resources: &'static mut StackResources<SOCKETS>,
) -> (Tls<'static>, Stack<'static>, EspAccel<'static>) {
    esp_println::logger::init_logger(log::LevelFilter::Info);

    info!("Starting...");

    heap_allocator!(#[ram(reclaimed)] size: RECLAIMED_RAM);

    let peripherals = esp_hal::init(esp_hal::Config::default());

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(
        timg0.timer0,
        esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT)
            .software_interrupt0,
    );

    #[cfg(not(any(feature = "esp32", feature = "esp32c2")))]
    let accel = EspAccel::new(peripherals.SHA, peripherals.RSA);

    #[cfg(feature = "esp32")]
    let accel = EspAccel::new(peripherals.RSA);

    #[cfg(feature = "esp32c2")]
    let accel = EspAccel::new(peripherals.SHA);

    let _trng_source = TrngSource::new(peripherals.RNG, peripherals.ADC1);

    let trng = mk_static!(Trng, Trng::try_new().unwrap());

    // Configure and start the Wifi first
    let (controller, wifi_interfaces) =
        esp_radio::wifi::new(peripherals.WIFI, esp_radio::wifi::Config::default()).unwrap();
    let config = embassy_net::Config::dhcpv4(Default::default());

    let seed = (trng.random() as u64) << 32 | trng.random() as u64;

    // Init network stack
    let (stack, runner) = embassy_net::new(wifi_interfaces.station, config, stack_resources, seed);

    spawner.spawn(connection(controller)).ok();
    spawner.spawn(net_task(runner)).ok();

    wait_ip(stack).await;

    (Tls::new(trng).unwrap(), stack, accel)
}

async fn wait_ip(stack: Stack<'_>) {
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
