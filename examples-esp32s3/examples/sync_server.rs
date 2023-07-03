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

    let tls = Session::new(
        socket,
        "test.local",
        Mode::Server,
        TlsVersion::Tls1_3,
        Certificates {
            certs: X509::pem(include_bytes!("../certs/rootCA.crt")).ok(),
            client_cert: X509::pem(include_bytes!("../certs/server.crt")).ok(),
            client_key: X509::pem(include_bytes!("../certs/server.key")).ok(),
            ..Default::default()
        },
    )
    .unwrap();
    // socket.listen(443).unwrap();

    // set_debug(0);
    // loop {
    //     socket.work();
    //
    //     if !socket.is_open() {
    //         socket.listen(80).unwrap();
    //     }
    //
    //     if socket.is_connected() {
    //         println!("New connection");
    //
    //         let mut time_out = false;
    //         let wait_end = current_millis() + 20 * 1000;
    //         let mut buffer = [0u8; 1024];
    //         let mut pos = 0;
    //
    //         loop {
    //             if let Ok(len) = socket.read(&mut buffer[pos..]) {
    //                 let to_print =
    //                     unsafe { core::str::from_utf8_unchecked(&buffer[..(pos + len)]) };
    //
    //                 if to_print.contains("\r\n\r\n") {
    //                     print!("{}", to_print);
    //                     println!();
    //                     break;
    //                 }
    //
    //                 pos += len;
    //             } else {
    //                 break;
    //             }
    //
    //             if current_millis() > wait_end {
    //                 println!("Timed out");
    //                 time_out = true;
    //                 break;
    //             }
    //         }
    //
    //         if !time_out {
    //             socket
    //                 .write_all(
    //                     b"HTTP/1.0 200 OK\r\n\r\n\
    //                 <html>\
    //                     <body>\
    //                         <h1>Hello Rust! Hello esp-mbedtls!</h1>\
    //                     </body>\
    //                 </html>\r\n\
    //                 ",
    //                 )
    //                 .unwrap();
    //
    //             socket.flush().unwrap();
    //         }
    //
    //         socket.close();
    //
    //         println!("Done\n");
    //         println!();
    //     }
    //
    //     // This seems to delay after a connection. Removed to allow instant connections
    //     //
    //     // let wait_end = current_millis() + 5 * 1000;
    //     // while current_millis() < wait_end {
    //     //     socket.work();
    //     // }
    // }
    loop {}

    //
    //
    // println!("Start tls connect");
    // let mut tls = tls.connect().unwrap();
    //
    // println!("Write to connection");
    // tls.write(b"GET /notfound HTTP/1.0\r\nHost: www.google.com\r\n\r\n")
    //     .unwrap();
}

static CLIENT_CERT: &str = "
-----BEGIN CERTIFICATE-----
MIIEwzCCAqsCAQEwDQYJKoZIhvcNAQELBQAwOTEaMBgGA1UEAwwRZXNwLW1iZWR0
bHMubG9jYWwxGzAZBgNVBAoMElNlcnZlciBDZXJ0aWZpY2F0ZTAeFw0yMzA0MTMy
MTQ2NTZaFw0yNDA0MTIyMTQ2NTZaMBYxFDASBgNVBAMMC2VzcC1tYmVkdGxzMIIC
IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtAuL/rdURchAf8SjQlc0o43V
mkMZfVDKpjq1YS97v7+X8SH/26box8X9N23qEzU8zYlZj+I+D3xrtVf2JwOK8IKj
EdbMEahkl9zA0moD/kR9W2DlAdJvKDf6DLQ/uKK1kw69oPdEir3RcmLFghZU5AYY
8CBqih4ZNAy7ZOJ9y/tx+Vp2Sne66hOg7rAKRZ1b1AISpBRaxHqBAxtXQy76s4t8
S1qSw1b+Ms2+MFEiBYSWGQ+Vqc9AsgmEBtsH0iUNLIfBUQNlmw8sy8vw0HnfFsyN
JsGRcLKUJ4FXNJIg96VpZazcP8tQYaoCrP9gd2FRaTBQarfTN7DinrswGC1BeUp7
7ftivZ7TPIe9megpb2FkSo034osb+zQzokoKjMIFSFHWovW4lFMgtLV/+Lqtmsoq
G1VGSLZIA78borreOq8z5xhY2rGdWNMxMe5Tu6GelN3OZH0bmQ7CNZM2FnMTMSRJ
ZxhYRvfw2T3ZFdgcCAtOIboPWuue4eAbwWkxCCvyHtns5LhrkwCFpZh7y0RLkGLV
IlsSiwpQ6CbqeKN9Vj232yGwyZ0caBS2LmFrlfN6qeqvjMLbPK556V7uh7nnOT8w
achoLJORFYvbhY4O+mmM8WyU8wrwL0uF8kobXSMtyemioJVGwIya7cQfmHbwFFta
evbTJusoOT7cYa5rbaECAwEAATANBgkqhkiG9w0BAQsFAAOCAgEACmhDPhFYGH6G
T7TgwFfgu9f7d6s/LLJPiO3Jtw0bcLdA2oFX+2MQ/vzGJmbvnK+yPCX7FrwWE0Iv
f71ZNdfdowSRhubKKBivVVeIK8S1v6yMYbHpjSYbs0H5ja+xWi3USVlOnU2uAfCZ
3UG1VjSKhm4ER/I27c0gsI9DmU80yzgmnr2POsHCBJdvL420AyiqLZ7QbPl5u1SV
bjz1AnoDwLyoA/qjeOSC7AsCsRTeq4C/cXR0Bf0JKIO2T5QSk1Z6IuZKbLkEoNT8
YK6h7qu3m2a18RZnxEHOQAUZsQDZluYCsooAQFPZL5puC9IvnoITM92rB08/aVbe
Z2ciqnjHI9JKjbMc4O7yhQakl2XcvqZVQdznxogiZO71dvKvOL5QzegrKzXSZm7x
7hXM0OaSFpAouh6AFKKCSqIxi09O8H0cNmO5HevQgg+M59eh/iJNKROucaBe1kW0
eRuLmIkHAh3sQwzf76nSq27o3NBs4stsYPh38EoWpTiYlXeu6zwzssj/YR46CBXt
Fy89f+Z1ypn2z7bhMNVJJJmy/JTySWW7tWuoRS2iNxTPrMFnskirWTCrVI7O7bwO
cJBebHHGzQVySXbqSCzOG1ebt1XacCA2to6LmydEEP+2TYhDyB3m576yYVRnCE2l
kVbOqRWrBKxccsLl+VrIggyWxcHov7w=
-----END CERTIFICATE-----
\0";

static PRIVATE_KEY: &str = "
-----BEGIN PRIVATE KEY-----
MIIJQQIBADANBgkqhkiG9w0BAQEFAASCCSswggknAgEAAoICAQC0C4v+t1RFyEB/
xKNCVzSjjdWaQxl9UMqmOrVhL3u/v5fxIf/bpujHxf03beoTNTzNiVmP4j4PfGu1
V/YnA4rwgqMR1swRqGSX3MDSagP+RH1bYOUB0m8oN/oMtD+4orWTDr2g90SKvdFy
YsWCFlTkBhjwIGqKHhk0DLtk4n3L+3H5WnZKd7rqE6DusApFnVvUAhKkFFrEeoED
G1dDLvqzi3xLWpLDVv4yzb4wUSIFhJYZD5Wpz0CyCYQG2wfSJQ0sh8FRA2WbDyzL
y/DQed8WzI0mwZFwspQngVc0kiD3pWllrNw/y1BhqgKs/2B3YVFpMFBqt9M3sOKe
uzAYLUF5Snvt+2K9ntM8h72Z6ClvYWRKjTfiixv7NDOiSgqMwgVIUdai9biUUyC0
tX/4uq2ayiobVUZItkgDvxuiut46rzPnGFjasZ1Y0zEx7lO7oZ6U3c5kfRuZDsI1
kzYWcxMxJElnGFhG9/DZPdkV2BwIC04hug9a657h4BvBaTEIK/Ie2ezkuGuTAIWl
mHvLREuQYtUiWxKLClDoJup4o31WPbfbIbDJnRxoFLYuYWuV83qp6q+Mwts8rnnp
Xu6Huec5PzBpyGgsk5EVi9uFjg76aYzxbJTzCvAvS4XyShtdIy3J6aKglUbAjJrt
xB+YdvAUW1p69tMm6yg5PtxhrmttoQIDAQABAoICAECS153+gKIahU+N5gP4JO/4
AcE3CaBRZq0h50W48wg9njAkwpA0F872qq/Doy1KbclF1rJtMVb6h+LdbnJlqeJC
6FuQj1ZR7+oriZit30rFo7QvV1NE9wsUsID38Na2vKrGoapmpNWh6Mm+tRnICqBR
s4YEClIJI37whhFTzkxnnWQSVtS0hnxHl/OjfbukCXhLWgYxKrDHQxgrKSv2YIIe
p/CaxoJ64+ayteC8aJhUCkVouoPRymFQWmLfEboEAeqTsfjtX/ayBZ3+QhtzaljR
+loJGLGzysE0eWNoeZx4XgnSapgSwnyUrir/2MhYRguVAXKVBZM2xMCrYD97k7xj
lgOyoif0K8DoZm0pJO2en1Nf7G8MF0G8gXCexhZw4g6cKchGKfu71LO9asyROJDs
ydJTT+jFgfkG2cOFFE0gnX+SJOpOlCF2N53syuu1hbRONuUJBJSuLPwS5+I6Un3p
gpxw0TSmxtI6BYtGtrGRXkpDHX5mPAl1oxNXjFTOLW5xbiCQBz/Co2DKqjIoZHg5
kqBnhvwuPTGXO8gFQjeBsMKpFYw+cizQ9czLuZ/xoFUer3b929iB1z2HpmEClDUY
pKW+M+JXxUT5dp7X66E+i3E3brLivSqPrjUJh5XY0MLoPGdHqcpVw51OTzQrJ8Gh
0giTXTf2WnbWIH67craFAoIBAQDMoF/IN1/WsMWbFqzKRwSVaYwGX/VxfCbVzcyo
qXSpRUccwd+UtObFSsKojHXZmZ/Ta1iW+If17XgVcfLjIdDb3AYAe74fRsM3gdDc
ORLCV8V3h+k2P5GXn9/6AvoOsMGC5bCbC9slCDb39a1fYR910/k37wQRk7XvIaOG
12XKIMc0YYyFjy/ojIo0YZzZvhCTfl3i/ZN/bngmLxadq3s3kKDrdjYCmRIjj9Bn
OEwAeB+HmJ9tZxolO1fhTsSI3OisG+/GURYVlDBUvuHyo/u32Di9unmX4ztLNUKU
VNjkBGZi2cSzhQ0G8ggA8or19tdocNkS99nc/iASLsvZmmefAoIBAQDhP0t+l961
nJlGHtVVtle4WpwIAWaLE2CTNTFM1VLgmZXyirjbyggKfifJdn184GtY6USqCxjm
qUMVxaxp5jCuCKSeIyNDr/gHbo14V6rRH9I4o3rJorCTxV/ZLPSztXrLQscxKUqo
+NnaXzTM65Fa1D6D5LQr3X8yravCIyFhSA/JkQelGg5RJqDBKF0cmMw2QKAtdhwR
yn1JHIqacJlLyg80Kwf3XiDQEPfl+0SDAv1o7ouwlTrFzYM5bHqiWduBbZAvOlC1
u9groD8H7D17CPfdZJKXuJX6coHF/yh7sFtWFhKWj/XxLeEn/b8jEdJyjSkzAYah
o45Y+vKdayK/AoIBAHBmW5agDC3i1fi1wN4vmm30Fy1dQnY+6xogPJ4czu84FbLP
L+AAao7O3RQ2a3nGsAsy+OucwxosgfzNpcxrw80xE77qOen2Nb9kuHRviUVlbxuU
dV8OFgxCjoZHYlH1d6ZOQu832P2DgKY9tikhMWXItSmrSgHZsGMViDzGTqxzytiU
CNtIZtmHcVcKk1zr0TEjhbDs9ztVU/wte2/KRRmlgS81tL9Ck7sjASfhvaW4ViFm
jZRLwQnYihJB8ST4q3n2soOuAMKDrvSuEXD18Ivw4mIdbzMmZ2iNbfAKl0TQwejk
k+7EU/6PriPPFtO67mH5MtP/fxWsJbO3LtRtwyMCggEAJ6YMk+wHt9Ao6r7iroO6
TSkl7gLRGgn/JepnEy85t29RhbAFeirF35L1TfEdha27N5tYCtaJO5DvzhVNlBaA
2yGKWIu22WNQNX6wSE6mMsl3J6EfK/8HNfu4M3JGYJvBUaYfiffKvJORRW8czDVr
EKHrnyvSyyXiDfmkEjg81/LnVIPC5L0BaCd0hIumWDJNP/+AMoBn0HnkM8piW20W
jtCyfGxWqqRXAkj6WfEwzh7onF/hFuQtxEO4pZMCwzEuAkpW5vlM27CFDKjYb3yW
FeIuPzpE05AaVktxrHiNl7gjW7Pm8bnFgP6ic3em/XVVpfRTHDdYi3tOwzrpGeyR
4QKCAQARoBRLPlq9cKEdGC78wrFh2M+1YD1QNI8Xqw1aIn5saGw8VGnhNhtGEEDD
zR3RFJhpHd6+9AjXKh1jm3rh6EAopRc81Evf9XxqCF2lL1COXhLYnObZEsWQKaN3
z7cK0cau0Vi0Yjt7/SfDTezX5FgPExd8wAhCKtEdlTuOh7ZYg6lG/xIDl2MqIbGE
9Jkge7fGChS5TMTPJMy6pxynCdrjVZGzyh3LwZpVz88ejDdC3XQAK2AjVlCR8igy
a68RAopHmneRG1h+5x7RBJ929Gpss9rsO4OBfhhPY/R/wBaIKMvJey9VC+V04d+z
Tqea5hb95hcAtU4GmjNM/Z3bB894
-----END PRIVATE KEY-----
\0";

static CERT: &str = "
-----BEGIN CERTIFICATE-----
MIIFVzCCAz+gAwIBAgINAgPlk28xsBNJiGuiFzANBgkqhkiG9w0BAQwFADBHMQsw
CQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU
MBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAw
MDAwWjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZp
Y2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwggIiMA0GCSqGSIb3DQEBAQUA
A4ICDwAwggIKAoICAQC2EQKLHuOhd5s73L+UPreVp0A8of2C+X0yBoJx9vaMf/vo
27xqLpeXo4xL+Sv2sfnOhB2x+cWX3u+58qPpvBKJXqeqUqv4IyfLpLGcY9vXmX7w
Cl7raKb0xlpHDU0QM+NOsROjyBhsS+z8CZDfnWQpJSMHobTSPS5g4M/SCYe7zUjw
TcLCeoiKu7rPWRnWr4+wB7CeMfGCwcDfLqZtbBkOtdh+JhpFAz2weaSUKK0Pfybl
qAj+lug8aJRT7oM6iCsVlgmy4HqMLnXWnOunVmSPlk9orj2XwoSPwLxAwAtcvfaH
szVsrBhQf4TgTM2S0yDpM7xSma8ytSmzJSq0SPly4cpk9+aCEI3oncKKiPo4Zor8
Y/kB+Xj9e1x3+naH+uzfsQ55lVe0vSbv1gHR6xYKu44LtcXFilWr06zqkUspzBmk
MiVOKvFlRNACzqrOSbTqn3yDsEB750Orp2yjj32JgfpMpf/VjsPOS+C12LOORc92
wO1AK/1TD7Cn1TsNsYqiA94xrcx36m97PtbfkSIS5r762DL8EGMUUXLeXdYWk70p
aDPvOmbsB4om3xPXV2V4J95eSRQAogB/mqghtqmxlbCluQ0WEdrHbEg8QOB+DVrN
VjzRlwW5y0vtOUucxD/SVRNuJLDWcfr0wbrM7Rv1/oFB2ACYPTrIrnqYNxgFlQID
AQABo0IwQDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
FgQU5K8rJnEaK0gnhS9SZizv8IkTcT4wDQYJKoZIhvcNAQEMBQADggIBAJ+qQibb
C5u+/x6Wki4+omVKapi6Ist9wTrYggoGxval3sBOh2Z5ofmmWJyq+bXmYOfg6LEe
QkEzCzc9zolwFcq1JKjPa7XSQCGYzyI0zzvFIoTgxQ6KfF2I5DUkzps+GlQebtuy
h6f88/qBVRRiClmpIgUxPoLW7ttXNLwzldMXG+gnoot7TiYaelpkttGsN/H9oPM4
7HLwEXWdyzRSjeZ2axfG34arJ45JK3VmgRAhpuo+9K4l/3wV3s6MJT/KYnAK9y8J
ZgfIPxz88NtFMN9iiMG1D53Dn0reWVlHxYciNuaCp+0KueIHoI17eko8cdLiA6Ef
MgfdG+RCzgwARWGAtQsgWSl4vflVy2PFPEz0tv/bal8xa5meLMFrUKTX5hgUvYU/
Z6tGn6D/Qqc6f1zLXbBwHSs09dR2CQzreExZBfMzQsNhFRAbd03OIozUhfJFfbdT
6u9AWpQKXCBfTkBdYiJ23//OYb2MI3jSNwLgjt7RETeJ9r/tSQdirpLsQBqvFAnZ
0E6yove+7u7Y/9waLd64NnHi/Hm3lCXRSHNboTXns5lndcEZOitHTtNCjv0xyBZm
2tIMPNuzjsmhDYAPexZ3FL//2wmUspO8IFgV6dtxQ/PeEMMA3KgqlbbC1j+Qa3bb
bP6MvPJwNQzcmRk13NfIRmPVNnGuV/u3gm3c
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFljCCA36gAwIBAgINAgO8U1lrNMcY9QFQZjANBgkqhkiG9w0BAQsFADBHMQsw
CQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU
MBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMjAwODEzMDAwMDQyWhcNMjcwOTMwMDAw
MDQyWjBGMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZp
Y2VzIExMQzETMBEGA1UEAxMKR1RTIENBIDFDMzCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAPWI3+dijB43+DdCkH9sh9D7ZYIl/ejLa6T/belaI+KZ9hzp
kgOZE3wJCor6QtZeViSqejOEH9Hpabu5dOxXTGZok3c3VVP+ORBNtzS7XyV3NzsX
lOo85Z3VvMO0Q+sup0fvsEQRY9i0QYXdQTBIkxu/t/bgRQIh4JZCF8/ZK2VWNAcm
BA2o/X3KLu/qSHw3TT8An4Pf73WELnlXXPxXbhqW//yMmqaZviXZf5YsBvcRKgKA
gOtjGDxQSYflispfGStZloEAoPtR28p3CwvJlk/vcEnHXG0g/Zm0tOLKLnf9LdwL
tmsTDIwZKxeWmLnwi/agJ7u2441Rj72ux5uxiZ0CAwEAAaOCAYAwggF8MA4GA1Ud
DwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEgYDVR0T
AQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUinR/r4XN7pXNPZzQ4kYU83E1HScwHwYD
VR0jBBgwFoAU5K8rJnEaK0gnhS9SZizv8IkTcT4waAYIKwYBBQUHAQEEXDBaMCYG
CCsGAQUFBzABhhpodHRwOi8vb2NzcC5wa2kuZ29vZy9ndHNyMTAwBggrBgEFBQcw
AoYkaHR0cDovL3BraS5nb29nL3JlcG8vY2VydHMvZ3RzcjEuZGVyMDQGA1UdHwQt
MCswKaAnoCWGI2h0dHA6Ly9jcmwucGtpLmdvb2cvZ3RzcjEvZ3RzcjEuY3JsMFcG
A1UdIARQME4wOAYKKwYBBAHWeQIFAzAqMCgGCCsGAQUFBwIBFhxodHRwczovL3Br
aS5nb29nL3JlcG9zaXRvcnkvMAgGBmeBDAECATAIBgZngQwBAgIwDQYJKoZIhvcN
AQELBQADggIBAIl9rCBcDDy+mqhXlRu0rvqrpXJxtDaV/d9AEQNMwkYUuxQkq/BQ
cSLbrcRuf8/xam/IgxvYzolfh2yHuKkMo5uhYpSTld9brmYZCwKWnvy15xBpPnrL
RklfRuFBsdeYTWU0AIAaP0+fbH9JAIFTQaSSIYKCGvGjRFsqUBITTcFTNvNCCK9U
+o53UxtkOCcXCb1YyRt8OS1b887U7ZfbFAO/CVMkH8IMBHmYJvJh8VNS/UKMG2Yr
PxWhu//2m+OBmgEGcYk1KCTd4b3rGS3hSMs9WYNRtHTGnXzGsYZbr8w0xNPM1IER
lQCh9BIiAfq0g3GvjLeMcySsN1PCAJA/Ef5c7TaUEDu9Ka7ixzpiO2xj2YC/WXGs
Yye5TBeg2vZzFb8q3o/zpWwygTMD0IZRcZk0upONXbVRWPeyk+gB9lm+cZv9TSjO
z23HFtz30dZGm6fKa+l3D/2gthsjgx0QGtkJAITgRNOidSOzNIb2ILCkXhAd4FJG
AJ2xDx8hcFH1mt0G/FX0Kw4zd8NLQsLxdxP8c4CU6x+7Nz/OAipmsHMdMqUybDKw
juDEI/9bfU1lcKwrmz3O2+BtjjKAvpafkmO8l7tdufThcV4q5O8DIrGKZTqPwJNl
1IXNDw9bg1kWRxYtnCQ6yICmJhSFm/Y3m6xv+cXDBlHz4n/FsRC6UfTd
-----END CERTIFICATE-----
\0";
