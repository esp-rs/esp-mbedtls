#![no_std]

use core::cell::RefCell;
use core::ffi::{c_char, c_int, c_uchar, c_void, CStr};
use core::marker::PhantomData;
use core::mem::size_of;
use core::ops::{Deref, DerefMut};
use core::ptr::NonNull;

use critical_section::Mutex;

use embedded_io::ErrorKind;

use esp_mbedtls_sys::bindings::*;

use rand_core::CryptoRng;

pub use cert::*;
pub use session::*;

pub(crate) mod fmt;

mod cert;
#[cfg(feature = "edge-nal")]
mod edge_nal;
#[cfg(any(
    feature = "esp32",
    feature = "esp32c3",
    feature = "esp32c6",
    feature = "esp32s2",
    feature = "esp32s3"
))]
mod esp_hal;
mod session;

/// Re-export of the `embedded-io` crate so that users don't have to explicitly depend on it
/// to use e.g. `write_all` or `read_exact`.
pub mod io {
    pub use embedded_io::*;
}

macro_rules! err {
    ($block:expr) => {{
        let res = $block;
        if res != 0 {
            Err(TlsError::MbedTlsError(res))
        } else {
            Ok(())
        }
    }};
}

pub(crate) use err;

/// Error type for TLS operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsError {
    /// A `Tls` instance has already been created
    AlreadyCreated,
    /// An unknown error occurred
    Unknown,
    /// Out of heap
    OutOfMemory,
    /// MBedTLS error
    MbedTlsError(i32),
    /// End of stream
    Eof,
    /// X509 certificate missing null terminator
    X509MissingNullTerminator,
    /// The X509 is in an unexpected format (PEM instead of DER and vice-versa)
    InvalidFormat,
    /// The client has given no certificates for the request
    NoClientCertificate,
    /// IO error
    Io(ErrorKind),
}

impl core::fmt::Display for TlsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AlreadyCreated => write!(f, "TLS already created"),
            Self::Unknown => write!(f, "Unknown error"),
            Self::OutOfMemory => write!(f, "Out of memory"),
            Self::MbedTlsError(e) => write!(f, "MbedTLS error: {e}"),
            Self::Eof => write!(f, "End of stream"),
            Self::X509MissingNullTerminator => {
                write!(f, "X509 certificate missing null terminator")
            }
            Self::InvalidFormat => write!(
                f,
                "The X509 is in an unexpected format (PEM instead of DER and vice-versa)"
            ),
            Self::NoClientCertificate => write!(f, "No client certificate"),
            Self::Io(e) => write!(f, "IO error: {e:?}"),
        }
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for TlsError {
    fn format(&self, f: defmt::Formatter<'_>) {
        match self {
            Self::AlreadyCreated => defmt::write!(f, "TLS already created"),
            Self::Unknown => defmt::write!(f, "Unknown error"),
            Self::OutOfMemory => defmt::write!(f, "Out of memory"),
            Self::MbedTlsError(e) => defmt::write!(f, "MbedTLS error: {}", e),
            Self::Eof => defmt::write!(f, "End of stream"),
            Self::X509MissingNullTerminator => {
                defmt::write!(f, "X509 certificate missing null terminator")
            }
            Self::InvalidFormat => defmt::write!(
                f,
                "The X509 is in an unexpected format (PEM instead of DER and vice-versa)"
            ),
            Self::NoClientCertificate => defmt::write!(f, "No client certificate"),
            Self::Io(e) => defmt::write!(f, "IO error: {:?}", debug2format!(e)),
        }
    }
}

impl core::error::Error for TlsError {}

impl embedded_io::Error for TlsError {
    fn kind(&self) -> embedded_io::ErrorKind {
        match self {
            Self::Io(e) => *e,
            _ => embedded_io::ErrorKind::Other,
        }
    }
}

/// A TLS self-test type
#[derive(enumset::EnumSetType, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TlsTest {
    Mpi,
    Rsa,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Aes,
    Md5,
}

impl core::fmt::Display for TlsTest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TlsTest::Mpi => write!(f, "MPI"),
            TlsTest::Rsa => write!(f, "RSA"),
            TlsTest::Sha1 => write!(f, "SHA1"),
            TlsTest::Sha224 => write!(f, "SHA224"),
            TlsTest::Sha256 => write!(f, "SHA256"),
            TlsTest::Sha384 => write!(f, "SHA384"),
            TlsTest::Sha512 => write!(f, "SHA512"),
            TlsTest::Aes => write!(f, "AES"),
            TlsTest::Md5 => write!(f, "MD5"),
        }
    }
}

static TLS_RNG: Mutex<RefCell<Option<&mut (dyn CryptoRng + Send)>>> =
    Mutex::new(RefCell::new(None));

/// A TLS instance
///
/// Represents an instance of the MbedTLS library.
/// Only one such instance can be active at any point in time.
pub struct Tls<'d>(PhantomData<&'d mut ()>);

impl<'d> Tls<'d> {
    /// Create a new instance of the `Tls` type.
    ///
    /// Note that there could be only one active `Tls` instance at any point in time,
    /// and the function will return an error if there is already an active instance.
    #[cfg(not(any(
        feature = "esp32",
        feature = "esp32c3",
        feature = "esp32c6",
        feature = "esp32s2",
        feature = "esp32s3"
    )))]
    pub fn new(rng: &'d mut (dyn CryptoRng + Send)) -> Result<Self, TlsError> {
        Self::create(rng)
    }

    pub(crate) fn create(rng: &'d mut (dyn CryptoRng + Send)) -> Result<Self, TlsError> {
        critical_section::with(|cs| {
            let created = TLS_RNG.borrow(cs).borrow().is_some();

            if created {
                return Err(TlsError::AlreadyCreated);
            }

            *TLS_RNG.borrow(cs).borrow_mut() = Some(unsafe {
                core::mem::transmute::<
                    &'d mut (dyn CryptoRng + Send),
                    &'static mut (dyn CryptoRng + Send),
                >(rng)
            });

            Ok(Self(PhantomData))
        })
    }

    pub(crate) fn release(&mut self) {
        critical_section::with(|cs| {
            *TLS_RNG.borrow(cs).borrow_mut() = None;
        });
    }

    /// Set the MbedTLS debug level (0 - 5)
    #[allow(unused)]
    pub fn set_debug(&mut self, level: u32) {
        #[cfg(not(target_os = "espidf"))]
        unsafe {
            mbedtls_debug_set_threshold(level as c_int);
        }
    }

    /// Run a self-test on the MbedTLS library
    ///
    /// # Arguments
    ///
    /// * `test` - The test to run
    /// * `verbose` - Whether to run the test in verbose mode
    pub fn self_test(&mut self, test: TlsTest, verbose: bool) -> bool {
        let verbose = verbose as _;

        let result = unsafe {
            match test {
                TlsTest::Mpi => mbedtls_mpi_self_test(verbose),
                TlsTest::Rsa => mbedtls_rsa_self_test(verbose),
                TlsTest::Sha1 => mbedtls_sha1_self_test(verbose),
                TlsTest::Sha224 => mbedtls_sha224_self_test(verbose),
                TlsTest::Sha256 => mbedtls_sha256_self_test(verbose),
                TlsTest::Sha384 => mbedtls_sha384_self_test(verbose),
                TlsTest::Sha512 => mbedtls_sha512_self_test(verbose),
                TlsTest::Aes => mbedtls_aes_self_test(verbose),
                TlsTest::Md5 => mbedtls_md5_self_test(verbose),
            }
        };

        result != 0
    }

    /// Get a reference to the `Tls` instance
    ///
    /// Each `Session` needs a reference to (the) active `Tls` instance
    /// throughout its lifetime.
    pub fn reference(&self) -> TlsReference<'_> {
        TlsReference(PhantomData)
    }
}

#[cfg(not(any(
    feature = "esp32",
    feature = "esp32c3",
    feature = "esp32c6",
    feature = "esp32s2",
    feature = "esp32s3"
)))]
impl<'d> Drop for Tls<'d> {
    fn drop(&mut self) {
        self.release();
    }
}

/// A reference to (the) active `Tls` instance
///
/// Used instead of just `&'a Tls` so that the invariant `'d` lifetime of the `Tls` instance
/// is not exposed in the `Session` type.
#[allow(unused)]
#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct TlsReference<'a>(PhantomData<&'a ()>);

/// The minimum TLS version that will be supported by a particular `Session` instance
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TlsVersion {
    /// TLS 1.2
    Tls1_2,
    /// TLS 1.3
    Tls1_3,
}

impl TlsVersion {
    fn mbed_tls_version(&self) -> u32 {
        match self {
            TlsVersion::Tls1_2 => 0x303,
            TlsVersion::Tls1_3 => 0x304,
        }
    }
}

/// An internal trait for MbedTLS structuremodeling the (security-induced) initialization and deinitialization
/// sequence for a number of MBedTLS structures
trait MInit {
    /// Initialize the structure
    fn init(&mut self) {}

    /// Deinitialize the structure
    fn deinit(&mut self) {}
}

impl MInit for mbedtls_ctr_drbg_context {
    fn init(&mut self) {
        unsafe {
            mbedtls_ctr_drbg_init(self);
        }
    }

    fn deinit(&mut self) {
        unsafe {
            mbedtls_ctr_drbg_free(self);
        }
    }
}

impl MInit for mbedtls_ssl_context {
    fn init(&mut self) {
        unsafe {
            mbedtls_ssl_init(self);
        }
    }

    fn deinit(&mut self) {
        unsafe {
            mbedtls_ssl_free(self);
        }
    }
}

impl MInit for mbedtls_ssl_config {
    fn init(&mut self) {
        unsafe {
            mbedtls_ssl_config_init(self);
        }
    }

    fn deinit(&mut self) {
        unsafe {
            mbedtls_ssl_config_free(self);
        }
    }
}

impl MInit for mbedtls_x509_crt {
    fn init(&mut self) {
        unsafe {
            mbedtls_x509_crt_init(self);
        }
    }

    fn deinit(&mut self) {
        unsafe {
            mbedtls_x509_crt_free(self);
        }
    }
}

impl MInit for mbedtls_pk_context {
    fn init(&mut self) {
        unsafe {
            mbedtls_pk_init(self);
        }
    }

    fn deinit(&mut self) {
        unsafe {
            mbedtls_pk_free(self);
        }
    }
}

/// A uniquely-owned box-like wrapper type for MbedTLS structures that need to be allocated/deallocated
/// using `mbedtls_calloc`/`mbedtls_free`, and initialized/deinitialized using the `MInit` trait
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct MBox<T>(NonNull<T>)
where
    T: MInit;

impl<T> MBox<T>
where
    T: MInit,
{
    /// Create a new MBox
    ///
    /// # Returns
    /// - Ok(MBox<T>) if the allocation was successful
    /// - Err(TlsError::OutOfMemory) if the allocation failed
    fn new() -> Result<Self, TlsError> {
        NonNull::new(unsafe { mbedtls_calloc(align_of::<T>(), size_of::<T>()) }.cast::<T>())
            .map(|mut ptr| {
                unsafe { ptr.as_mut() }.init();

                Self(ptr)
            })
            .ok_or(TlsError::OutOfMemory)
    }

    /// Get a reference to the inner value
    fn as_ref(&self) -> &T {
        unsafe { self.0.as_ref() }
    }

    /// Get a mutable reference to the inner value
    fn as_mut(&mut self) -> &mut T {
        unsafe { self.0.as_mut() }
    }
}

impl<T> Deref for MBox<T>
where
    T: MInit,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<T> DerefMut for MBox<T>
where
    T: MInit,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut()
    }
}

impl<T> Drop for MBox<T>
where
    T: MInit,
{
    fn drop(&mut self) {
        self.as_mut().deinit();

        unsafe {
            mbedtls_free(self.0.as_ptr() as *mut c_void);
        }
    }
}

/// A reference-counted `Rc`-like wrapper type for MbedTLS structures that need to be allocated/deallocated
/// using `mbedtls_calloc`/`mbedtls_free`, and initialized/deinitialized using the `MInit` trait
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
struct MRc<T>(NonNull<(T, usize)>)
where
    T: MInit;

impl<T> MRc<T>
where
    T: MInit,
{
    /// Create a new MRc
    fn new() -> Result<Self, TlsError> {
        NonNull::new(
            unsafe { mbedtls_calloc(align_of::<(T, usize)>(), size_of::<(T, usize)>()) }
                .cast::<(T, usize)>(),
        )
        .map(|mut ptr| {
            unsafe { ptr.as_mut() }.0.init();

            Self(ptr)
        })
        .ok_or(TlsError::OutOfMemory)
    }

    /// Get a reference to the inner value
    fn as_ref(&self) -> &T {
        &unsafe { self.0.as_ref() }.0
    }
}

impl<T> Clone for MRc<T>
where
    T: MInit,
{
    fn clone(&self) -> Self {
        let mut ptr = self.0;

        unsafe { ptr.as_mut() }.1 += 1;

        Self(ptr)
    }
}

impl<T> Deref for MRc<T>
where
    T: MInit,
{
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl<T> Drop for MRc<T>
where
    T: MInit,
{
    fn drop(&mut self) {
        unsafe { self.0.as_mut() }.1 -= 1;

        if unsafe { self.0.as_mut() }.1 == 0 {
            unsafe { self.0.as_mut() }.0.deinit();

            unsafe {
                mbedtls_free(self.0.as_ptr() as *mut c_void);
            }
        }
    }
}

/// Outputs the MbedTLS debug messages to the log
pub(crate) unsafe extern "C" fn mbedtls_dbg_print(
    _arg: *mut c_void,
    lvl: i32,
    file: *const c_char,
    line: i32,
    msg: *const c_char,
) {
    let file = CStr::from_ptr(file);
    let msg = CStr::from_ptr(msg);

    let file = file.to_str().unwrap_or("???").trim();
    let msg = msg.to_str().unwrap_or("???").trim();

    match lvl {
        0 => error!("{} ({}:{}) {}", lvl, file, line, msg),
        1 => warn!("{} ({}:{}) {}", lvl, file, line, msg),
        2 => debug!("{} ({}:{}) {}", lvl, file, line, msg),
        _ => trace!("{} ({}:{}) {}", lvl, file, line, msg),
    }
}

pub(crate) unsafe extern "C" fn mbedtls_rng(
    _param: *mut c_void,
    buf: *mut c_uchar,
    len: usize,
) -> c_int {
    let buf = core::slice::from_raw_parts_mut(buf, len as _);

    critical_section::with(|cs| {
        let mut rng = TLS_RNG.borrow(cs).borrow_mut();

        rng.as_mut().unwrap().fill_bytes(buf);
    });

    0
}

#[no_mangle]
unsafe extern "C" fn mbedtls_psa_external_get_random(
    _ctx: *mut (),
    output: *mut c_uchar,
    out_size: usize,
    output_len: *mut usize,
) -> c_int {
    *output_len = out_size;
    mbedtls_rng(core::ptr::null_mut(), output, out_size)
}

#[cfg(not(target_os = "espidf"))]
#[no_mangle]
unsafe extern "C" fn mbedtls_platform_zeroize(dst: *mut c_uchar, len: u32) {
    for i in 0..len as isize {
        dst.offset(i).write_volatile(0);
    }
}

#[cfg(feature = "esp32c6")]
#[no_mangle]
unsafe extern "C" fn memchr(ptr: *const u8, ch: u8, count: usize) -> *const u8 {
    for i in 0..count {
        if ptr.add(i).read() == ch {
            return ptr.add(i);
        }
    }

    return core::ptr::null();
}
