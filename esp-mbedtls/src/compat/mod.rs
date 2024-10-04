/// Implements edge-nal traits
#[cfg(feature = "edge-nal")]
pub mod edge_nal_compat;

#[no_mangle]
extern "C" fn rand() -> crate::c_ulong {
    unsafe { crate::random() }
}

pub struct StrBuf {
    buffer: [u8; 512],
    len: usize,
}

impl StrBuf {
    pub fn new() -> StrBuf {
        StrBuf {
            buffer: [0u8; 512],
            len: 0,
        }
    }

    pub fn append(&mut self, s: &str) {
        let mut idx: usize = self.len;
        s.chars().for_each(|c| {
            self.buffer[idx] = c as u8;
            idx += 1;
        });
        self.len = idx;
    }

    pub fn append_char(&mut self, c: char) {
        let mut idx: usize = self.len;
        self.buffer[idx] = c as u8;
        idx += 1;
        self.len = idx;
    }

    pub unsafe fn as_str_ref(&self) -> &str {
        core::str::from_utf8_unchecked(&self.buffer[..self.len])
    }
}

impl core::fmt::Write for StrBuf {
    fn write_str(&mut self, s: &str) -> Result<(), core::fmt::Error> {
        self.append(s);
        Ok(())
    }
}
