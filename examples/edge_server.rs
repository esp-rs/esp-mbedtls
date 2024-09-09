//! Example for an HTTPS server using [edge-http](https://github.com/ivmarkov/edge-net) as the
//! HTTPS server implementation, and `esp-mbedtls` for the TLS layer.
//!
//! Note: If you run out of heap memory, you need to increase `heap_size` in cfg.toml
//!
//! This example uses self-signed certificate. Your browser may display an error.
//! You have to enable the exception to then proceed, of if using curl, use the flag `-k`.
#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]
#![feature(impl_trait_in_assoc_type)]

#[doc(hidden)]
pub use esp_hal as hal;

use edge_http::io::server::{Connection, Handler, Server};
use edge_http::io::Error;
use edge_http::Method;
use edge_nal_embassy::{Tcp, TcpBuffers};

use embedded_io_async::{ErrorType, Read, Write};

use embassy_net::{Config, Stack, StackResources};

use embassy_executor::Spawner;
use embassy_time::{Duration, Timer};
use esp_backtrace as _;
use esp_mbedtls::{set_debug, Certificates, TlsVersion};
use esp_mbedtls::{TlsError, X509};
use esp_println::logger::init_logger;
use esp_println::println;
use esp_wifi::wifi::{
    ClientConfiguration, Configuration, WifiController, WifiDevice, WifiEvent, WifiStaDevice,
    WifiState,
};
use esp_wifi::{initialize, EspWifiInitFor};
use hal::{
    clock::ClockControl, peripherals::Peripherals, rng::Rng, system::SystemControl,
    timer::timg::TimerGroup,
};

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

/// Number of sockets used for the HTTPS server
const SERVER_SOCKETS: usize = 2;

/// Total number of sockets used for the application
const SOCKET_COUNT: usize = 1 + 1 + SERVER_SOCKETS; // DHCP + DNS + Server

const RX_SIZE: usize = 4096;
const TX_SIZE: usize = 2048;

/// HTTPS server evaluated at compile time with socket count and buffer size.
pub type HttpsServer = Server<SERVER_SOCKETS, RX_SIZE, 32>;

#[esp_hal_embassy::main]
async fn main(spawner: Spawner) -> ! {
    init_logger(log::LevelFilter::Info);

    let mut peripherals = Peripherals::take();
    let system = SystemControl::new(peripherals.SYSTEM);
    let clocks = ClockControl::max(system.clock_control).freeze();

    let timg0 = TimerGroup::new(peripherals.TIMG0, &clocks);

    let init = initialize(
        EspWifiInitFor::Wifi,
        timg0.timer0,
        Rng::new(peripherals.RNG),
        peripherals.RADIO_CLK,
        &clocks,
    )
    .unwrap();

    let wifi = peripherals.WIFI;
    let (wifi_interface, controller) =
        esp_wifi::wifi::new_with_mode(&init, wifi, WifiStaDevice).unwrap();

    cfg_if::cfg_if! {
        if #[cfg(feature = "esp32")] {
            let timg1 = TimerGroup::new(peripherals.TIMG1, &clocks);
            esp_hal_embassy::init(&clocks, timg1.timer0);
        } else {
            use esp_hal::timer::systimer::{SystemTimer, Target};
            let systimer = SystemTimer::new(peripherals.SYSTIMER).split::<Target>();
            esp_hal_embassy::init(&clocks, systimer.alarm0);
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
            mk_static!(
                StackResources<SOCKET_COUNT>,
                StackResources::<SOCKET_COUNT>::new()
            ),
            seed
        )
    );

    spawner.spawn(connection(controller)).ok();
    spawner.spawn(net_task(&stack)).ok();

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

    set_debug(0);

    let server = mk_static!(HttpsServer, HttpsServer::new());
    let buffers = mk_static!(TcpBuffers<SERVER_SOCKETS, TX_SIZE, RX_SIZE>, TcpBuffers::<SERVER_SOCKETS, TX_SIZE, RX_SIZE>::new());
    let tls_buffers = mk_static!(
        esp_mbedtls::asynch::TlsBuffers::<RX_SIZE, TX_SIZE>,
        esp_mbedtls::asynch::TlsBuffers::<RX_SIZE, TX_SIZE>::new()
    );
    let tcp = mk_static!(
        Tcp<'_, WifiDevice<'_, WifiStaDevice>, SERVER_SOCKETS, TX_SIZE, RX_SIZE>,
        Tcp::new(stack, buffers)
    );

    let certificates = Certificates {
        // Use self-signed certificates
        certificate: X509::pem(concat!(include_str!("./certs/certificate.pem"), "\0").as_bytes())
            .ok(),
        private_key: X509::pem(concat!(include_str!("./certs/private_key.pem"), "\0").as_bytes())
            .ok(),
        ..Default::default()
    };

    loop {
        let tls_acceptor = esp_mbedtls::asynch::TlsAcceptor::new(
            tcp,
            tls_buffers,
            443,
            TlsVersion::Tls1_2,
            certificates,
        )
        .await
        .with_hardware_rsa(&mut peripherals.RSA);
        match server.run(tls_acceptor, HttpHandler, Some(15_000)).await {
            Ok(_) => {}
            Err(Error::Io(TlsError::MbedTlsError(-30592))) => {
                println!("Fatal message: Please enable the exception for a self-signed certificate in your browser");
            }
            Err(error) => {
                // panic!("{:?}", error);
                log::error!("{:?}", error);
            }
        }
    }
}

struct HttpHandler;

impl<'b, T, const N: usize> Handler<'b, T, N> for HttpHandler
where
    T: Read + Write,
    T::Error: Send + Sync,
{
    type Error = Error<<T as ErrorType>::Error>;

    async fn handle(&self, connection: &mut Connection<'b, T, N>) -> Result<(), Self::Error> {
        println!("Got new connection");
        let headers = connection.headers()?;

        if !matches!(headers.method, Some(Method::Get)) {
            connection
                .initiate_response(405, Some("Method Not Allowed"), &[])
                .await?;
        } else if !matches!(headers.path, Some("/")) {
            connection
                .initiate_response(404, Some("Not Found"), &[])
                .await?;
        } else {
            connection
                .initiate_response(200, Some("OK"), &[("Content-Type", "text/plain")])
                .await?;

            connection.write_all(b"Hello world!").await?;
        }

        Ok(())
    }
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
