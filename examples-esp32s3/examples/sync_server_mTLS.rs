//! Example for a sync server.
//! Contains a basic server implementation to test mbedtls in server mode.
//!
//! This example is configured to use mTLS. If you send a request, without passing
//! certificates, you will get an error. Theses certificates below are generated
//! to work is the configured CA:
//!
//! cert.pem
//! ```text
//! -----BEGIN CERTIFICATE-----
//! MIIEvjCCAqYCAQEwDQYJKoZIhvcNAQELBQAwLjEaMBgGA1UEAwwRZXNwLW1iZWR0
//! bHMubG9jYWwxEDAOBgNVBAoMB1Jvb3QgQ0EwHhcNMjMwNzA3MjIzNDM1WhcNMjQw
//! NzA2MjIzNDM1WjAcMRowGAYDVQQDDBFlc3AtbWJlZHRscy5sb2NhbDCCAiIwDQYJ
//! KoZIhvcNAQEBBQADggIPADCCAgoCggIBAKoyrbQxPl/Z5J2rhL5OlkDte3+C5OSQ
//! vlQf/Cvx3wkeGJgkzxf/B0QVItf+VOo+cAvHYCSYjpFAM0+unVx8UY2Pf33B/b9f
//! Zpsedy91J075Jfng8Oc5UijvzwF8gn9Dyb2GttUm3Qm4BLDz6Dx5VD2oTMhvfGb6
//! RzOj2MpALYVsQn8WaQJeeEOoyqjqZ7oRUDHN8U7nxResNi7T2OWNh/+su/6Z+Uqd
//! eGq6n4ixdBcZ7hOIM98BgIXgUQ2VT179zfBlsFYTyBr186AX/yqNGYH6E/y3rMbt
//! SST/96peF5scGABWwyyuN1elOm57+6QQWCiM0MZOKJLakHm34Zmb/z+dAKNMpfhb
//! 602TgjIR6Eu/2Z8RaGfdgVSvl4tenFb4Gu3IyH7sHohD715VF20sDRXX0R4grCn+
//! gLXmheGbAxZ4QU0Ilh0MOBtuWMjEGStvfgZiEz0XpeTEK+y38iOuM0ABs0Ub6VNN
//! OPfVixSAy3PM3+cBOwYdrEA8huAMiijvx1k/3OQzpckvo97EMMs/rrlkgHNpxNxH
//! 0Mbfa3AuDCHnnf86C58KpvFnjLZaU8+/VVafeGTRXuI/nZBPVXZDh/xOVIeNOI93
//! GCP9ma2dLciua6Hc5/+1zYQznA7BhipqyE8hW3hCihzza6BLmbP1FDoJEWyThX9X
//! vOhDWqrlLTyBAgMBAAEwDQYJKoZIhvcNAQELBQADggIBAGQfusfxUdH42dyt93W+
//! /grR+auC28NaBBvCx3U99wdAOAYkvmjOT2dx/MgNf3kZNL9QBwXMYOic0Ek9vkie
//! AUU2CgZv9xptNZHRfAUEq7tRHOns2vsHR9ExnUo+fr83D6BYL4kQiAwWhtKEUn5V
//! rwmDgUAMAHHlQFWjFgByovAEdTNbSY0XEwtfIuI1s47+pGONwQtYqFg6VQOqGJBC
//! 9bd1kD1IVJcLG1/E7wuRi/vpJCP+8T6CnYBMe6cmFi5S5o6p3KLJX33gDcKCaQPr
//! 1fBqxdRI9ezgcBRETK8kXeO/5ip53B+cg1ZIBo6Odz3JpeKhZVqI3KN4f8lRr9yb
//! Cm8TfLOMY7fGGJcUffAcb/jItC0BmMm0bL0ZTmpxE6ULwxPWEy2zAPGX4h1ZfrAS
//! rDj7TupNeHsf69/aJHA0q8Mjn+p09kMIwkJD120Q84PjKYmkd/ZnCR6d3Rg5N3/r
//! DbfFx21l8NO4knySC0R3u2Q5qU5nMIrt6kL0hKGvrVkTli9o16taKSO6RvNgcC7+
//! 6/d0XwOclAHMJ8laVoPDANQc3u6Q5vheHtk3IIKI6V54FHo+ehvVubgnWYYPSwwA
//! W7SsDG9901j1sbvZU3Imo3ItsRacsPk4g05GQK0I9eR1pAo/GSCr8yoi/oS32otC
//! qOPP5MoWs8sLu6Hq4B2bBZmq
//! -----END CERTIFICATE-----
//! ```
//!
//! key.pem
//! ```text
//! -----BEGIN PRIVATE KEY-----
//! MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQCqMq20MT5f2eSd
//! q4S+TpZA7Xt/guTkkL5UH/wr8d8JHhiYJM8X/wdEFSLX/lTqPnALx2AkmI6RQDNP
//! rp1cfFGNj399wf2/X2abHncvdSdO+SX54PDnOVIo788BfIJ/Q8m9hrbVJt0JuASw
//! 8+g8eVQ9qEzIb3xm+kczo9jKQC2FbEJ/FmkCXnhDqMqo6me6EVAxzfFO58UXrDYu
//! 09jljYf/rLv+mflKnXhqup+IsXQXGe4TiDPfAYCF4FENlU9e/c3wZbBWE8ga9fOg
//! F/8qjRmB+hP8t6zG7Ukk//eqXhebHBgAVsMsrjdXpTpue/ukEFgojNDGTiiS2pB5
//! t+GZm/8/nQCjTKX4W+tNk4IyEehLv9mfEWhn3YFUr5eLXpxW+BrtyMh+7B6IQ+9e
//! VRdtLA0V19EeIKwp/oC15oXhmwMWeEFNCJYdDDgbbljIxBkrb34GYhM9F6XkxCvs
//! t/IjrjNAAbNFG+lTTTj31YsUgMtzzN/nATsGHaxAPIbgDIoo78dZP9zkM6XJL6Pe
//! xDDLP665ZIBzacTcR9DG32twLgwh553/OgufCqbxZ4y2WlPPv1VWn3hk0V7iP52Q
//! T1V2Q4f8TlSHjTiPdxgj/ZmtnS3Irmuh3Of/tc2EM5wOwYYqashPIVt4Qooc82ug
//! S5mz9RQ6CRFsk4V/V7zoQ1qq5S08gQIDAQABAoIB/wzkAkz1Z+Y816FPGWD3SGEi
//! ia2dN+WO8y7IPWSZpzeOCI1ZuWGiT/3rcjmlUqhlRNi9TnSI+7Ryx5+/4uDbZea2
//! nNsOvQoNfpu1K5BKYpxwdQkvELCuKzYJUv82eWRc0V1wKHfD43P7ORJXonBvJUoP
//! JlCFD0fJULYLK22vDHYwx1WUXm6YbrYKeXK57wZ9k5/G5gFxsyn4lTnQCl18R2QF
//! psxP8gFUAMlWIKRe+/9M2zDp8dojPoVoQOr0mDCbI1W9BKh6YvxyMFloWhxRipuN
//! lVgw9mOdsAjUchLh7McJzEqNoQgcGAAhuqMLyds5l0QhrahpQBGj0owATgWaWICi
//! PVQKvGG2IUGU5+QdFoYtUT4IPq+RwNU70OGjriKeskhZjN6sCv9wJjrBxwerzURT
//! qMQVLNCu9JqLi0UEttBMJsXB3KNx+bKVLKi8Eb+OYIbauRMpbMkMrwEMrnEXU34M
//! HhiChYXu65rQGxXEU7wCJeIovmcaQEs5bPYWW1T/8UYJFa8ZbQJUK21Ggo2jdHIR
//! 8Mg39mqC3Af+LuRMA4FxxlPaeHkwHYdliqvta+CfcWN9p/Dipwd4g3S9Tx4bwAui
//! zHqQvHLFYxw2v8XxEgAIH2bWuqfvj+dzOlnpqDQI9hKlD0Q4G964COuAzBgp2brY
//! pqEvaNaEvTMwWLNwar0CggEBAM82bvUbTxFkU+4GhsSNLYb7wAH4FM2Xbe9yzdMZ
//! 7LKGnF57ZVDyTXb+Gf9usSk/R5JFK1raqHRIPyzKvVHWAzg0Bi/sGnI06mVebae1
//! JuS6Ki0mzukwTn0L0EItwSXZH12RLZUcvXcgJFyptlzF64iM2F00VY9TIbDtHazf
//! cEoYzmaA6HqawRkTzlwdNvgctDDItkG8Um6O3yWKSIC+oAYty45ngAoOA89oLiS9
//! ovkopaS5ZRQo60zPx+Zxlv0G/nxA6N+6hCupYuLXaSrEnbvN3mDA/H1CG9eYZBIi
//! RYpXWh2LKORxldBMsmuxykBXewwKiMCd8IGOL4BRXTdbd40CggEBANJFN5xRQQ27
//! hhcZxjgP/fAKToI2j7NMmhXDRO2kP8ZhynjdvHnbxGCbsOKAVME+ivE9WSAZ730g
//! 8f8+7n74fAfJHCTNn1zdnKfMaCHlIEjwDfaFH1VhVCOcXu2FtXHa1D688zmQMsu2
//! YFIZcj6DZ2+PDfaN5N05GJMkeTPIMBA13zGp/g1ptKoKp5Wpm2CQX3ONKzQnxJxu
//! jt2o8+U0etWF8TEvRiFHE9EWz9oWVVWiXn2mLys0e6eNHlfhYitPcdpGTaVbx/Tx
//! +PVQcnDyHHlmh5UjUfNED4nJV06jYTpiLUN3Nc8zD76DugUbqvkXgTTyygv1c//E
//! q2+Y68xZccUCggEAak4MwqaN++gyvsyOW0vqbXO+X8Q8N/VWKyAExCZqrnQsyLQZ
//! mFuWrlNSVx8cuIKEX2ApC+VdwrpF3t7sHY3j/PODsRY5wxmunu7A5uci2vk/Jgbg
//! 4/UqbzCeWTVL//TSCJiwf+1Mrk7JGNjge9v2KAnJ/pcYxfzqLfCX5taCryDm0uOT
//! YUL/ibQFjHBYgRWIw/ZUuoi46YtWo9W7uIETa9gWtCoZIA9smP1jnunDMHxP7qBG
//! YP9VKAT5Exp3UbxC1tAeKJlxsUynNKU6iPxxx6WoTo7zefdufT7rJ/p5Hq4Nx1Zb
//! VkeHimOurV1622OF9vl4iwj8GBsv927Gmd3NCQKCAQEArqQOrCZQgbdeh5FAsQ+X
//! OedVjZEDiUf2Ml0cwsPItFxEbl68S/ncAOFO6NDtlBL+E5+AhskDwEm8tOLv80Uu
//! vsiqN2cRFXB6zGNZmc1UI0A+WKH4hFFyMKGPtnd3XDkET5df7E934Pp4xbecy48Y
//! Oe/3CPCRRaxGXO/OOtPqF4ym8/jcqQdCpnhy+DsGcg13OeHmIEtnYQXyYugQqi4M
//! V4wH53H8LWd7bg4kVF54Qce582Iziw7sJR1wNk1b290AEuqRUuYIDclrnVRTuLte
//! KvadZaEQT5wXy7kOaqIH/xXLwl0gtBcU3IdL2TJBruF2zyNX7NbQoX4XZXj9X5xq
//! gQKCAQEApcefXJBwlqa7FkR1ugFDOqBTkB8prgpqMSGFzkq/NNxnmYlGW02OyJtJ
//! pm6u+9PcWPYs5/TwR/I/+JKlQgfHEFGhyqIDydYROvFi+PomaiK4QgfZqWpmMPBX
//! LvbwaS4lBmRIhXnJxtwpqYsEbq2ICmQnELMM+NZEQeK9AI5pwxoD25fMvkgDQzmp
//! FsCSduzqtINwMYQsZ+RQmDAKGjxngiOBMXRVjUuGqzT/0/VO35DJ058c2Wln3Ak7
//! eUXB1nTkTui+ZdWnipxdIqsuCXnMtuiGaSYnpulbld3r0UAgOb+q5x2i6uUyb0dr
//! aGTeS83wCwybWvk9U8pmo6eHiRh/dw==
//! -----END PRIVATE KEY-----
//! ```
//!
//! Test with curl:
//! ```bash
//! curl https://<IP>/ --cert cert.pem --key private_key.pem -k
//! ```
#![no_std]
#![no_main]
#![allow(non_snake_case)]

use embedded_io::blocking::*;
use embedded_svc::{
    ipv4::Interface,
    wifi::{ClientConfiguration, Configuration, Wifi},
};
use esp_backtrace as _;
use esp_mbedtls::{set_debug, Mode, TlsError, TlsVersion, X509};
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
use smoltcp::iface::SocketStorage;

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
                    ca_chain: X509::pem(CA_CERT.as_bytes()).ok(),
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

// Root CA used to authenticate clients
static CA_CERT: &str = "
-----BEGIN CERTIFICATE-----
MIIFPTCCAyWgAwIBAgIUOzicSI1PcoKPon56eYsYFLV755cwDQYJKoZIhvcNAQEL
BQAwLjEaMBgGA1UEAwwRZXNwLW1iZWR0bHMubG9jYWwxEDAOBgNVBAoMB1Jvb3Qg
Q0EwHhcNMjMwNzA3MjIzMzAyWhcNMjQwNzA2MjIzMzAyWjAuMRowGAYDVQQDDBFl
c3AtbWJlZHRscy5sb2NhbDEQMA4GA1UECgwHUm9vdCBDQTCCAiIwDQYJKoZIhvcN
AQEBBQADggIPADCCAgoCggIBAOqN84HIKAtA9YTYEAfmiZN9QiVIdpWTa2WuJg9z
hnk3RgdE2F/QIgxdV6m5hVp3JCZ2uPDxClazukJ7mTy2rS+OydPRBtVlkm2SlGx7
/ZhTW/cUO0iA3yYRpkAgXZuqYpu5Qki+mbB+A6ug+2al42mxEOb+hzCZ+ju+7aMn
mRO69UOr+p4zHASnDnIdh4A0m5dOytdvkFYrI8Sg4Z0NpapVMwgoVKurQdNh2ROB
mJlz10T0RV5kqhYiuLxZMmTiJ1cku7MW6zCX0Gxt04oFKavrjinmA8o+PYwd/eM7
R6TesAhNGwV7xNCH9UVAbJ9fqY/BRGUMeb2yuGqTXjpzKmiJtPmdbFm0WDt/xiNc
BUr72/EJFxyAt1bdj3LwkVvV8Mni6uaK3JsMUlJs4VvFKg50fy+JYWnP2rQT/d4a
1knOvQUQzJuKlHhCPb1bIQB8qbtP46bGaMzHzPme6haGni7Eu/kdSB/gtHuTB/7f
vADRs5KHKdWPLr/24n/gl2Dd7VnYaBo+xYfYSeR15rq6giOwX8SsFzY0cjMQAjh4
YkU6aa549xFjLkCrNPOc0BJwHkygyB1KB/ueZ2qyW1gYDx/XdQKAjJpuzwDfThI7
aO/TvP8mPjTjW7ZLvGuFaW5EpghX7cIc81hdPpo5Fcw8OJu51nLzqeLU7OldGR1C
pyvlAgMBAAGjUzBRMB0GA1UdDgQWBBTJ8XBS3rW8/wHvSx48yMgfs7hMAjAfBgNV
HSMEGDAWgBTJ8XBS3rW8/wHvSx48yMgfs7hMAjAPBgNVHRMBAf8EBTADAQH/MA0G
CSqGSIb3DQEBCwUAA4ICAQAJlg2OcDaTuVnqH3kHuZlSwsDoO7s7OXKagYRhyxcq
VO75NoJxKTUWIU0tPUJUVOAlxgCiRlumCGyFxfbFNccjyzcYXc6eWyMXWnpxShET
u/wDUvw3DahpyDNypgpgXDQTQs/HIuC1wKMC4SfRXayLblOWjO3c7rmFItNR1Eyj
H0uNWGMXFoNPvuZ9XZoC7Ts/wipva1ELsqTmGmXEk+YIsLNqvA5muq0xvdJ5cfTu
alm9Ivf6RA68PJNiecM+GCaMGU78qWh0L6n+devFzTzcjTe8GDIEoBeS2ECYdC+k
UDOA1zBo9HqL+Cg+CpHyMrnA1INvVx1CMDz3tjZKHKNAmk6xyGRct5tHqys67CNP
pZw7BNIE9Psu7pGQtfQ0ophE/eETqKI3tJ9h0/2YuywRqGSmwJeE1Rx6ds/F+m20
pOvblhjsmciUqiRYGHRGbTYEAWh1OcYjDm1U0C1nqFP+dsbqg35ag7UP1u8OdERL
d3Jgilad7RPIpj8DcUwnR/wcFCGEgXUhw+4/0+9FZkC5R9UX5a0v612coujdt/oE
/2iWwLTL0EzcXtAu6xBdwhnaVyHJQi8NRKX5vEYVn49R+tzr24fPf42q5Ak9Zyat
N7b0XDC+VIqHBisCHY9Pz8Rb7hFcUu84YRV79SAnLvm842Iklsk/mlhm+Ui+0qkg
6Q==
-----END CERTIFICATE-----
\0";

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
