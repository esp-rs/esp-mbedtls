use core::ffi::{c_int, c_uchar};
use core::marker::PhantomData;
use core::ops::Deref;

use digest::Digest;

use super::WorkArea;

pub use sha1::*;
pub use sha256::*;
pub use sha512::*;

pub(crate) mod sha1;
pub(crate) mod sha256;
pub(crate) mod sha512;

pub trait MbedtlsDigest {
    fn output_size(&self, work_area: &[u8]) -> usize;

    fn init(&self, work_area: &mut [u8]);

    fn reset(&self, work_area: &mut [u8]);

    fn update(&self, work_area: &mut [u8], data: &[u8]);

    fn finish(&self, work_area: &mut [u8], output: &mut [u8]);

    fn clone(&self, src_work_area: &[u8], dst_workarea: &mut [u8]);
}

impl<T: Deref> MbedtlsDigest for T
where
    T::Target: MbedtlsDigest,
{
    fn output_size(&self, work_area: &[u8]) -> usize {
        self.deref().output_size(work_area)
    }

    fn init(&self, work_area: &mut [u8]) {
        self.deref().init(work_area);
    }

    fn reset(&self, work_area: &mut [u8]) {
        self.deref().reset(work_area);
    }

    fn update(&self, work_area: &mut [u8], data: &[u8]) {
        self.deref().update(work_area, data);
    }

    fn finish(&self, work_area: &mut [u8], output: &mut [u8]) {
        self.deref().finish(work_area, output);
    }

    fn clone(&self, src_work_area: &[u8], dst_workarea: &mut [u8]) {
        self.deref().clone(src_work_area, dst_workarea);
    }
}

pub struct RustCryptoDigest<T>(PhantomData<fn() -> T>);

impl<T> Default for RustCryptoDigest<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> RustCryptoDigest<T> {
    pub const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T> MbedtlsDigest for RustCryptoDigest<T>
where
    T: Digest, /*Clone*/
{
    fn output_size(&self, _work_area: &[u8]) -> usize {
        <T as Digest>::output_size()
    }

    fn init(&self, work_area: &mut [u8]) {
        unsafe { work_area.cast_mut_maybe::<Option<T>>() }.write(Some(T::new()));
    }

    fn reset(&self, work_area: &mut [u8]) {
        *unsafe { work_area.cast_mut() } = Some(T::new());
    }

    fn update(&self, work_area: &mut [u8], data: &[u8]) {
        Digest::update(
            unsafe { work_area.cast_mut::<Option<T>>() }
                .as_mut()
                .unwrap(),
            data,
        );
    }

    fn finish(&self, work_area: &mut [u8], output: &mut [u8]) {
        output.copy_from_slice(
            &unsafe { work_area.cast_mut::<Option<T>>() }
                .take()
                .unwrap()
                .finalize(),
        );
    }

    fn clone(&self, _src_work_area: &[u8], _dst_work_area: &mut [u8]) {
        unimplemented!()
        // TODO: Needs a Clone bound on T which is not yet possible with `esp-hal`
        // unsafe {
        //     (dst_work_area.cast_mut::<T>() as *mut T).write(src_work_area.cast::<T>().clone());
        // }
    }
}

#[inline(always)]
unsafe fn digest_init<T: WorkArea>(algo: &dyn MbedtlsDigest, work_area: *mut T) {
    algo.init(work_area.as_mut().unwrap().area_mut());
}

#[inline(always)]
unsafe fn digest_free<T: WorkArea>(algo: &dyn MbedtlsDigest, work_area: *mut T) {
    algo.reset(work_area.as_mut().unwrap().area_mut());
}

#[inline(always)]
unsafe fn digest_clone<T: WorkArea>(
    algo: &dyn MbedtlsDigest,
    src_work_area: *const T,
    dst_work_area: *mut T,
) {
    algo.clone(
        src_work_area.as_ref().unwrap().area(),
        dst_work_area.as_mut().unwrap().area_mut(),
    );
}

#[inline(always)]
unsafe fn digest_starts<T: WorkArea>(algo: &dyn MbedtlsDigest, work_area: *mut T) -> c_int {
    algo.reset(work_area.as_mut().unwrap().area_mut());

    0
}

#[inline(always)]
unsafe fn digest_update<T: WorkArea>(
    algo: &dyn MbedtlsDigest,
    work_area: *mut T,
    input: *const c_uchar,
    ilen: usize,
) -> c_int {
    if ilen > 0 {
        let data = unsafe { core::slice::from_raw_parts(input, ilen) };

        algo.update(work_area.as_mut().unwrap().area_mut(), data);
    }

    0
}

#[inline(always)]
unsafe fn digest_finish<T: WorkArea>(
    algo: &dyn MbedtlsDigest,
    work_area: *mut T,
    output: *mut c_uchar,
) -> c_int {
    let output_slice = unsafe {
        core::slice::from_raw_parts_mut(
            output,
            algo.output_size(work_area.as_ref().unwrap().area()),
        )
    };

    algo.finish(work_area.as_mut().unwrap().area_mut(), output_slice);

    0
}
