use core::ffi::VaListImpl;
use core::fmt::Write;

#[no_mangle]
extern "C" fn putchar() {
    todo!()
}

#[no_mangle]
pub unsafe extern "C" fn snprintf(dst: *mut u8, n: u32, format: *const u8, args: ...) -> i32 {
    vsnprintf(dst, n, format, args)
}

#[no_mangle]
extern "C" fn vsnprintf(
    dst: *mut u8,
    _max_len: u32,
    format: *const u8,
    mut args: VaListImpl,
) -> i32 {
    unsafe {
        let fmt_str_ptr = format;
        let mut res_str = StrBuf::new();

        let strbuf = StrBuf::from(fmt_str_ptr);
        let s = strbuf.as_str_ref();

        let mut format_char = ' ';
        let mut is_long = false;
        let mut found = false;
        for c in s.chars().into_iter() {
            if !found {
                if c == '%' {
                    found = true;
                }

                if !found {
                    res_str.append_char(c);
                }
            } else {
                if c.is_numeric() || c == '-' || c == 'l' || c == 'z' {
                    if c == 'l' {
                        is_long = true;
                    }
                    // ignore
                } else {
                    // a format char
                    format_char = c;
                }
            }

            if found && format_char != ' ' {
                // have to format an arg
                match format_char {
                    'd' => {
                        if is_long {
                            let v = args.arg::<i32>();
                            write!(res_str, "{}", v).ok();
                        } else {
                            let v = args.arg::<i32>();
                            write!(res_str, "{}", v).ok();
                        }
                    }

                    'u' => {
                        let v = args.arg::<u32>();
                        write!(res_str, "{}", v).ok();
                    }

                    'p' => {
                        let v = args.arg::<u32>();
                        write!(res_str, "0x{:x}", v).ok();
                    }

                    'X' => {
                        let v = args.arg::<u32>();
                        write!(res_str, "{:02x}", (v & 0xff000000) >> 24).ok();
                    }

                    'x' => {
                        let v = args.arg::<u32>();
                        write!(res_str, "{:02x}", v).ok();
                    }

                    's' => {
                        let v = args.arg::<u32>() as *const i8;
                        let str = core::ffi::CStr::from_ptr(v);
                        let str = match str.to_str() {
                            Ok(str) => str,
                            Err(_err) => "Invalid",
                        };
                        write!(res_str, "{}", str).ok();
                    }

                    'c' => {
                        let v = args.arg::<u8>();
                        if v != 0 {
                            write!(res_str, "{}", v as char).ok();
                        }
                    }

                    _ => {
                        write!(res_str, "<UNKNOWN{}>", format_char).ok();
                    }
                }

                format_char = ' ';
                found = false;
                is_long = false;
            }
        }

        // TODO apply max_len
        core::ptr::copy_nonoverlapping(res_str.buffer.as_ptr(), dst, res_str.len);
        let idx = res_str.len as isize;
        *(dst.offset(idx)) = 0;

        idx as i32
    }
}

#[no_mangle]
extern "C" fn rand() {
    todo!()
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

    pub unsafe fn from(c_str: *const u8) -> StrBuf {
        let mut res = StrBuf {
            buffer: [0u8; 512],
            len: 0,
        };

        let mut idx: usize = 0;
        while *(c_str.offset(idx as isize)) != 0 {
            res.buffer[idx] = *(c_str.offset(idx as isize));
            idx += 1;
        }

        res.len = idx;
        res
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

pub(crate) fn ensure_null_terminated(s: &str) -> (*const u8, u32) {
    let bytes = s.as_bytes();

    // String is already null-terminated
    if bytes.last() == Some(&0) {
        (s.as_ptr(), s.len() as u32)
    } else {
        // Create a new null-terminated string from bytes
        let mut buffer = [0; 4096];
        // Get the min between buffer or string
        let len = core::cmp::min(bytes.len(), buffer.len() - 1);
        buffer[..len].copy_from_slice(&bytes[..len]);
        buffer[len] = 0;
        // Bump len by 1, since we added a null terminating character
        (buffer.as_ptr(), (len + 1) as u32)
    }
}
