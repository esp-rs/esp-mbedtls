use core::ffi::c_uchar;
use core::marker::PhantomData;

use esp_mbedtls_sys::bindings::*;

use super::{err, MRc, TlsError};

/// Format type for [X509]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CertificateFormat {
    PEM,
    DER,
}

/// Holds a X509 certificate
///
/// # Examples
/// Initialize with a PEM certificate
/// ```
/// const CERTIFICATE: &[u8] = include_bytes!("certificate.pem");
/// let cert = X509::pem(CERTIFICATE).unwrap();
/// ```
///
/// Initialize with a DER certificate
/// ```
/// const CERTIFICATE: &[u8] = include_bytes!("certificate.der");
/// let cert = X509::der(CERTIFICATE);
/// ```
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct X509<'a> {
    bytes: &'a [u8],
    format: CertificateFormat,
}

impl<'a> X509<'a> {
    /// Reads certificate in pem format from bytes
    ///
    /// # Error
    /// This function returns [TlsError::X509MissingNullTerminator] if the certificate
    /// doesn't end with a null-byte.
    pub fn pem(bytes: &'a [u8]) -> Result<Self, TlsError> {
        if let Some(len) = X509::get_null(bytes) {
            // Get a slice of only the certificate bytes including the \0
            let bytes = unsafe { core::slice::from_raw_parts(bytes.as_ptr(), len + 1) };
            Ok(Self {
                bytes,
                format: CertificateFormat::PEM,
            })
        } else {
            Err(TlsError::X509MissingNullTerminator)
        }
    }

    /// Reads certificate in der format from bytes
    ///
    /// *Note*: This function assumes that the size of the size is the exact
    /// length of the certificate
    pub fn der(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            format: CertificateFormat::DER,
        }
    }

    /// Returns the bytes of the certificate
    pub fn data(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the encoding format of a certificate
    pub fn format(&self) -> CertificateFormat {
        self.format
    }

    /// Returns the length of the certificate
    pub(crate) fn len(&self) -> usize {
        self.data().len()
    }

    /// Returns a pointer to the data for parsing
    pub(crate) fn as_ptr(&self) -> *const c_uchar {
        self.data().as_ptr().cast()
    }

    /// Gets the first null byte in a slice
    fn get_null(bytes: &[u8]) -> Option<usize> {
        bytes.iter().position(|&byte| byte == 0)
    }
}

/// A X509 certificate or certificate chain.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Certificate<'d> {
    pub(crate) crt: MRc<mbedtls_x509_crt>,
    _t: PhantomData<&'d ()>,
}

impl Certificate<'static> {
    /// Parse an X509 certificate into RAM by making a copy
    ///
    /// # Arguments
    ///
    /// * `certificate` - The X509 certificate in PEM or DER format
    ///
    /// # Errors
    ///
    /// This will return an error if an error occurs during parsing such as passing a DER encoded
    /// certificate in a PEM format, and vice-versa.
    pub fn new(certificate: X509<'_>) -> Result<Self, TlsError> {
        let crt = MRc::new()?;

        match certificate.format {
            CertificateFormat::PEM => err!(unsafe {
                mbedtls_x509_crt_parse(
                    &*crt as *const _ as *mut _,
                    certificate.as_ptr(),
                    certificate.len(),
                )
            }),
            CertificateFormat::DER => err!(unsafe {
                mbedtls_x509_crt_parse_der(
                    &*crt as *const _ as *mut _,
                    certificate.as_ptr(),
                    certificate.len(),
                )
            }),
        }
        .map_err(|err| {
            if matches!(err, TlsError::MbedTlsError(-8576)) {
                TlsError::InvalidFormat
            } else {
                err
            }
        })?;

        Ok(Self {
            crt,
            _t: PhantomData,
        })
    }
}

impl<'d> Certificate<'d> {
    /// Parse an X509 certificate without making a copy in RAM. This requires that the underlying data
    /// lives for the lifetime of the certificate.
    /// Note: This is currently only supported for DER encoded certificates
    ///
    /// # Arguments
    ///
    /// * `certificate` - The X509 certificate in DER format only
    ///
    /// # Errors
    ///
    /// This will return an error if an error occurs during parsing.
    /// [TlsError::InvalidFormat] will be returned if a PEM encoded certificate is passed.
    pub fn new_no_copy(certificate: X509<'d>) -> Result<Self, TlsError> {
        // Currently no copy is only supported by DER certificates
        if matches!(certificate.format(), CertificateFormat::PEM) {
            return Err(TlsError::InvalidFormat);
        }

        let crt = MRc::new()?;

        err!(unsafe {
            mbedtls_x509_crt_parse_der_nocopy(
                &*crt as *const _ as *mut _,
                certificate.as_ptr(),
                certificate.len(),
            )
        })
        .map_err(|err| {
            if matches!(err, TlsError::MbedTlsError(-8576)) {
                TlsError::InvalidFormat
            } else {
                err
            }
        })?;

        Ok(Self {
            crt,
            _t: PhantomData,
        })
    }
}

/// A private key
#[derive(Debug, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct PrivateKey(pub(crate) MRc<mbedtls_pk_context>);

impl PrivateKey {
    /// Parse an X509 private key into RAM and returns a wrapped pointer if successful.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The X509 private key in DER or PEM format
    /// * `password` - The optional password if the private key is password protected
    ///
    /// # Errors
    ///
    /// This will return an error if an error occurs during parsing such as passing a DER encoded
    /// private key in a PEM format, and vice-versa.
    pub fn new(private_key: X509<'_>, password: Option<&str>) -> Result<Self, TlsError> {
        let pk = MRc::new()?;

        let (password_ptr, password_len) = if let Some(password) = password {
            (password.as_ptr(), password.len())
        } else {
            (core::ptr::null(), 0)
        };

        err!(unsafe {
            mbedtls_pk_parse_key(
                &*pk as *const _ as *mut _,
                private_key.as_ptr(),
                private_key.len(),
                password_ptr,
                password_len,
                None,
                core::ptr::null_mut(),
            )
        })?;

        Ok(Self(pk))
    }
}
