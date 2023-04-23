#![no_std]
#![no_main]

use embedded_io::blocking::*;
use embedded_svc::{
    ipv4::Interface,
    wifi::{ClientConfiguration, Configuration, Wifi},
};
use esp_backtrace as _;
use esp_mbedtls::Session;
use esp_mbedtls::{set_debug, Mode, TlsVersion};
use esp_println::{logger::init_logger, print, println};
use esp_wifi::{
    current_millis, initialize,
    wifi::{utils::create_network_interface, WifiMode},
    wifi_interface::WifiStack,
};
use hal::{
    clock::{ClockControl, CpuClock},
    peripherals::Peripherals,
    prelude::*,
    Rng, Rtc,
};
use smoltcp::{iface::SocketStorage, wire::Ipv4Address};

const SSID: &str = env!("SSID");
const PASSWORD: &str = env!("PASSWORD");

#[entry]
fn main() -> ! {
    init_logger(log::LevelFilter::Info);

    let peripherals = Peripherals::take();
    let system = peripherals.SYSTEM.split();
    let clocks = ClockControl::configure(system.clock_control, CpuClock::Clock160MHz).freeze();

    let mut rtc = Rtc::new(peripherals.RTC_CNTL);

    // Disable watchdog timers
    rtc.swd.disable();
    rtc.rwdt.disable();

    let (wifi, _) = peripherals.RADIO.split();
    let mut socket_set_entries: [SocketStorage; 3] = Default::default();
    let (iface, device, mut controller, sockets) =
        create_network_interface(wifi, WifiMode::Sta, &mut socket_set_entries);
    let wifi_stack = WifiStack::new(iface, device, sockets, current_millis);

    let timer = hal::systimer::SystemTimer::new(peripherals.SYSTIMER);
    initialize(
        timer.alarm0,
        Rng::new(peripherals.RNG),
        system.radio_clock_control,
        &clocks,
    )
    .unwrap();

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

    println!("Making HTTP request");
    let mut rx_buffer = [0u8; 1536];
    let mut tx_buffer = [0u8; 1536];
    let mut socket = wifi_stack.get_socket(&mut rx_buffer, &mut tx_buffer);

    socket.work();

    socket
        .open(Ipv4Address::new(62, 210, 201, 125), 443) // certauth.cryptomix.com
        .unwrap();

    set_debug(0);

    #[cfg(not(feature = "encrypted_private_key"))]
    let certificates = Certificates {
        certs: Some(CERT),
        client_cert: Some(CLIENT_CERT),
        client_key: Some(PRIVATE_KEY),
        password: None,
    };

    #[cfg(feature = "encrypted_private_key")]
    let certificates = Certificates {
        certs: Some(CERT),
        client_cert: Some(CLIENT_CERT_WITH_PASSWORD),
        client_key: Some(PRIVATE_KEY_WITH_PASSWORD),
        password: Some("password\0"),
    };

    let tls = Session::new(
        socket,
        "certauth.cryptomix.com",
        Mode::Client,
        TlsVersion::Tls1_3,
        certificates,
    )
    .unwrap();

    println!("Start tls connect");
    let mut tls = tls.connect().unwrap();

    println!("Write to connection");
    tls.write(b"GET /json/ HTTP/1.0\r\nHost: certauth.cryptomix.com\r\n\r\n")
        .unwrap();

    println!("Read from connection");
    let mut buffer = [0u8; 4096];
    loop {
        match tls.read(&mut buffer) {
            Ok(len) => {
                print!("{}", unsafe {
                    core::str::from_utf8_unchecked(&buffer[..len as usize])
                });
            }
            Err(_) => {
                println!();
                break;
            }
        }
    }
    println!("Done");

    loop {}
}

#[cfg(feature = "encrypted_private_key")]
static CLIENT_CERT_WITH_PASSWORD: &str = "
-----BEGIN CERTIFICATE-----
MIIEyTCCArECAQEwDQYJKoZIhvcNAQELBQAwOTEaMBgGA1UEAwwRZXNwLW1iZWR0
bHMubG9jYWwxGzAZBgNVBAoMElNlcnZlciBDZXJ0aWZpY2F0ZTAeFw0yMzA0MTgy
MTU0MzVaFw0yNDA0MTcyMTU0MzVaMBwxGjAYBgNVBAMMEWVzcC1tYmVkdGxzLmxv
Y2FsMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAzOPa2uYa58aou0up
ycBMpL4jMPqVvn/vlKIn1xaK9Na2ZzJQWMad0nzt/2EHKWbTkgDZ0NcL7lAvXypo
kDM9uOyGVk4Gh/32xLytsdxVgBpxDq+XvJTAamuYYEa49btu6028fZIj0o/mNE3Z
wLjNnlXhVkYBP44ye4cr7s5eJha2SHZatih1RKYRJyxcP9jtFEAyQj48vdxARV7j
M814ZCNvC08mbgNoiI0W8mPOwXj3JcmU/1Abqe6mflyMkgeIgxX9F3QHMfgBUmsO
Z1YNf58wrOITGxS8JUZiJk1n6n+lM0AERYCxXOsf50jNyn+0Oy4Hqj/KNf1+lwcY
EVbgI7V3tQQwpp9pa99EusimgxFH7KtIKJCz3vcu0H/SgguTkEibC5g161CpPOIH
bJOYQlcNLSM+N7Hca8sHF5VJv7YxShFRO8pnWV60vfZvy/o2hHKLz5w09hXlYW6b
xKuhg8wq9at7JeCb70DT1wGxgjPBL3zOqVFAB5Hq0FQu340cK8jELXhse3yD7GE9
QtXkszBjNfDsHRkLokLJPVJPq42ZYvFW9zBTtdzLOgALcTzAO39bzc8iZMHdAGdX
m1wLyqqm0Eg4Vigvj8XDPRCndawI6NOssvzQLSqxFkulFuZbI6gNwrQWWPzZAn1z
kEWFFM0Wri1emXxp/YcJaECUgTcCAwEAATANBgkqhkiG9w0BAQsFAAOCAgEAFPJO
cwd6VDxcQbHqjk2jiDGRv+H+zU2rZcZmBEKP01mDHFCCKVad6Frvr1PDUJ+r4mt3
Qm3N2o9EvLpQGhqvQ1PMQAZV0k7MvG4pRSrb4XE/v2eY8vxuLOTk2THH83NQydVF
16FAA3iBA9BXy7WspbAbfmKLAi8zdLsvSR02s8N1A1ghgTbf+O8p4J/MSPWuWFjJ
KR6vfJY3tdC6E0WqVabZRnfUO/3Bn0Gu/j9WV3Az8dAGtD/S3gDhoKCAenDCIE70
FsIFjmC6HMjfWgxtFKJo/oIEkH7I9JK4rIddsmMC/yYBB6VII/bDOsP0DoHu8N72
iFUzH1dQgYZ4VHGJOjyh4Ff/Gq06TnFVC14sSZd0hx4YGlulqp6lo9QQN2pXjX2J
h/TSiWq+eSGI2OGMfsd4UWuaWAoJs49Y6G+OWB5whZmKDnCUVkTAQKmdDCDJYY87
3sqVHzulGdbdQJj+kmpY4psNCWTC0bSnbnKYr9ZMklOdOUdY8nnnci8PW32oTlgI
daobGvFy9V035+zvYX/vvsw6oXXxa2OeDcRW5Ugg0+7xKW/vzEvoBOLdYmb0ymBb
31WOxm3eTczSqWa10GBJNmTLhCLEQBi9XOtCD1kDNfAIifE5KKY9Z0sv/7/mH3u9
n3p7AD8fvlXuxnmDVFCmgafTnsX45hdiU2SQ54Y=
-----END CERTIFICATE-----
\0";

#[cfg(feature = "encrypted_private_key")]
static PRIVATE_KEY_WITH_PASSWORD: &str = "
-----BEGIN ENCRYPTED PRIVATE KEY-----
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
nM+yE3f3cEwBq/R016M8+g==
-----END ENCRYPTED PRIVATE KEY-----
\0";

#[cfg(not(feature = "encrypted_private_key"))]
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

#[cfg(not(feature = "encrypted_private_key"))]
static PRIVATE_KEY: &str = "
-----BEGIN PRIVATE KEY-----
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
Tqea5hb95hcAtU4GmjNM/Z3bB894
-----END PRIVATE KEY-----
\0";

static CERT: &str = "
-----BEGIN CERTIFICATE-----
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
XXDaAQQ3
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw
WhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cP
R5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdx
sxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8Zutm
NHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxg
Z3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG
/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB
Af8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaA
FHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw
AoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw
Oi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB
gt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6W
PTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wl
ikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQz
CkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BIm
lJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4
avAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2
yJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1O
yK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90Ids
hCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+
HlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6Zv
MldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqX
nLRbwHOoq7hHwg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFYDCCBEigAwIBAgIQQAF3ITfU6UK47naqPGQKtzANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQwM1ow
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQCt6CRz9BQ385ueK1coHIe+3LffOJCMbjzmV6B493XC
ov71am72AE8o295ohmxEk7axY/0UEmu/H9LqMZshftEzPLpI9d1537O4/xLxIZpL
wYqGcWlKZmZsj348cL+tKSIG8+TA5oCu4kuPt5l+lAOf00eXfJlII1PoOK5PCm+D
LtFJV4yAdLbaL9A4jXsDcCEbdfIwPPqPrt3aY6vrFk/CjhFLfs8L6P+1dy70sntK
4EwSJQxwjQMpoOFTJOwT2e4ZvxCzSow/iaNhUd6shweU9GNx7C7ib1uYgeGJXDR5
bHbvO5BieebbpJovJsXQEOEO3tkQjhb7t/eo98flAgeYjzYIlefiN5YNNnWe+w5y
sR2bvAP5SQXYgd0FtCrWQemsAXaVCg/Y39W9Eh81LygXbNKYwagJZHduRze6zqxZ
Xmidf3LWicUGQSk+WT7dJvUkyRGnWqNMQB9GoZm1pzpRboY7nn1ypxIFeFntPlF4
FQsDj43QLwWyPntKHEtzBRL8xurgUBN8Q5N0s8p0544fAQjQMNRbcTa0B7rBMDBc
SLeCO5imfWCKoqMpgsy6vYMEG6KDA0Gh1gXxG8K28Kh8hjtGqEgqiNx2mna/H2ql
PRmP6zjzZN7IKw0KKP/32+IVQtQi0Cdd4Xn+GOdwiK1O5tmLOsbdJ1Fu/7xk9TND
TwIDAQABo4IBRjCCAUIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw
SwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vYXBwcy5pZGVudHJ1
c3QuY29tL3Jvb3RzL2RzdHJvb3RjYXgzLnA3YzAfBgNVHSMEGDAWgBTEp7Gkeyxx
+tvhS5B1/8QVYIWJEDBUBgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEB
ATAwMC4GCCsGAQUFBwIBFiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQu
b3JnMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmwuaWRlbnRydXN0LmNvbS9E
U1RST09UQ0FYM0NSTC5jcmwwHQYDVR0OBBYEFHm0WeZ7tuXkAXOACIjIGlj26Ztu
MA0GCSqGSIb3DQEBCwUAA4IBAQAKcwBslm7/DlLQrt2M51oGrS+o44+/yQoDFVDC
5WxCu2+b9LRPwkSICHXM6webFGJueN7sJ7o5XPWioW5WlHAQU7G75K/QosMrAdSW
9MUgNTP52GE24HGNtLi1qoJFlcDyqSMo59ahy2cI2qBDLKobkx/J3vWraV0T9VuG
WCLKTVXkcGdtwlfFRjlBz4pYg1htmf5X6DYO8A4jqv2Il9DjXA6USbW1FzXSLr9O
he8Y4IWS6wY7bCkjCWDcRQJMEhg76fsO3txE+FiYruq9RUWhiF1myv4Q6W+CyBFC
Dfvp7OOGAN6dEOM4+qR9sdjoSYKEBpsr6GtPAQw4dy753ec5
-----END CERTIFICATE-----
\0";
