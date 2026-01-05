//! Run crypto self tests to ensure their functionnality
#![no_std]
#![no_main]

use core::cell::RefCell;
use core::ffi::c_int;
use core::fmt::Write as _;

use critical_section::Mutex;
use embassy_executor::Spawner;

use esp_alloc::heap_allocator;
use esp_backtrace as _;
use esp_hal::ram;
use esp_hal::rsa::RsaBackend;
use esp_hal::sha::ShaBackend;
use esp_hal::timer::timg::TimerGroup;
use esp_mbedtls::sys::accel::esp::digest as accel_digest;
use esp_mbedtls::sys::accel::esp::exp_mod as accel_exp_mod;
use esp_mbedtls::sys::hook::digest;
use esp_mbedtls::sys::hook::exp_mod;
use esp_mbedtls::sys::self_test::MbedtlsSelfTest;
use esp_metadata_generated::memory_range;
use esp_radio as _;

use log::info;

extern crate alloc;

const HEAP_SIZE: usize = 100 * 1024;

const RECLAIMED_RAM: usize =
    memory_range!("DRAM2_UNINIT").end - memory_range!("DRAM2_UNINIT").start;

esp_bootloader_esp_idf::esp_app_desc!();

static RNG: Mutex<RefCell<Option<esp_hal::rng::Rng>>> = Mutex::new(RefCell::new(None));

#[esp_rtos::main]
async fn main(_s: Spawner) {
    esp_println::logger::init_logger(log::LevelFilter::Info);

    info!("Starting...");

    heap_allocator!(size: HEAP_SIZE - RECLAIMED_RAM);
    heap_allocator!(#[ram(reclaimed)] size: RECLAIMED_RAM);

    let peripherals = esp_hal::init(esp_hal::Config::default());

    critical_section::with(|cs| {
        *RNG.borrow(cs).borrow_mut() = Some(esp_hal::rng::Rng::new());
    });

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(
        timg0.timer0,
        #[cfg(target_arch = "riscv32")]
        esp_hal::interrupt::software::SoftwareInterruptControl::new(peripherals.SW_INTERRUPT)
            .software_interrupt0,
    );

    let mut sw_cycles = [0; 20];
    let mut hw_cycles = [0; 20];

    run_tests(false, &mut sw_cycles);

    let mut sha = ShaBackend::new(peripherals.SHA);
    let _sha_backend = sha.start();

    let mut rsa = RsaBackend::new(peripherals.RSA);
    let _rsa_backend = rsa.start();

    static SHA1: accel_digest::EspSha1 = accel_digest::EspSha1::new();
    #[cfg(not(feature = "esp32"))]
    static SHA224: accel_digest::EspSha224 = accel_digest::EspSha224::new();
    static SHA256: accel_digest::EspSha256 = accel_digest::EspSha256::new();
    #[cfg(any(feature = "esp32", feature = "esp32s2", feature = "esp32s3"))]
    static SHA384: accel_digest::EspSha384 = accel_digest::EspSha384::new();
    #[cfg(any(feature = "esp32", feature = "esp32s2", feature = "esp32s3"))]
    static SHA512: accel_digest::EspSha512 = accel_digest::EspSha512::new();

    static EXP_MOD: accel_exp_mod::EspExpMod = accel_exp_mod::EspExpMod::new();

    unsafe {
        digest::hook_sha1(Some(&SHA1));
        #[cfg(not(feature = "esp32"))]
        digest::hook_sha224(Some(&SHA224));
        digest::hook_sha256(Some(&SHA256));
        #[cfg(any(feature = "esp32", feature = "esp32s2", feature = "esp32s3"))]
        digest::hook_sha384(Some(&SHA384));
        #[cfg(any(feature = "esp32", feature = "esp32s2", feature = "esp32s3"))]
        digest::hook_sha512(Some(&SHA512));
        exp_mod::hook_exp_mod(Some(&EXP_MOD));
    }

    run_tests(true, &mut hw_cycles);

    // | Hash Algorithm | Software (cycles) | Hardware (cycles) | Hardware Faster (x times) |
    // |----------------|-------------------|-------------------|---------------------------|
    // | SHA-1          |      3,390,785    |         896,889   |           3.78            |
    // | SHA-224        |      8,251,799    |         898,344   |           9.19            |
    // | SHA-256        |      8,237,932    |         901,709   |           9.14            |
    // | SHA-384        |     13,605,806    |         799,532   |           17.02           |
    // | SHA-512        |     13,588,104    |         801,556   |           16.95           |

    info!("=== SUMMARY ===");
    info!("| Hash Algorithm | Software (cycles) | Hardware (cycles) | Hardware Faster (x times) |");
    info!("|----------------|-------------------|-------------------|---------------------------|");
    for (index, test) in enumset::EnumSet::<MbedtlsSelfTest>::all()
        .iter()
        .enumerate()
    {
        let mut test_name = heapless::String::<14>::new();
        write!(&mut test_name, "{:?}", test).unwrap();

        info!(
            "| {:14} | {:17} | {:17} | {:25.2} |",
            test_name,
            sw_cycles[index],
            hw_cycles[index],
            if hw_cycles[index] != 0 {
                (sw_cycles[index] as f64) / (hw_cycles[index] as f64)
            } else {
                0.0
            }
        );
    }
}

fn run_tests(hw_accel: bool, summary: &mut [u64]) {
    info!(
        ">>> Running tests {} hardware acceleration",
        if hw_accel { "WITH" } else { "WITHOUT" }
    );

    for mut test in enumset::EnumSet::<MbedtlsSelfTest>::all() {
        let before = cycles();

        test.run(false);

        let after = cycles();

        let cycles = after.checked_sub(before).unwrap_or(0);

        let mut test_name = heapless::String::<14>::new();
        write!(&mut test_name, "{:?}", test).unwrap();

        info!("Test {:14} took {:17?} cycles", test_name, cycles);

        summary[test as usize] = cycles;
    }
}

fn cycles() -> u64 {
    #[cfg(any(feature = "esp32", feature = "esp32s2", feature = "esp32s3"))]
    {
        esp_hal::xtensa_lx::timer::get_cycle_count() as u64
    }

    #[cfg(not(any(feature = "esp32", feature = "esp32s2", feature = "esp32s3")))]
    {
        use esp_hal::timer::systimer::{SystemTimer, Unit};
        SystemTimer::unit_value(Unit::Unit0)
    }
}

// The RSA self-tests unfortunately directly use the `rand` symbol
#[no_mangle]
unsafe extern "C" fn rand() -> c_int {
    critical_section::with(|cs| {
        (RNG.borrow(cs).borrow_mut().as_mut().unwrap().random() % i32::MAX as u32) as _
    })
}
