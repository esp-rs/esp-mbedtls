pub mod digest;
pub mod exp_mod;

pub trait WorkArea {
    fn area(&self) -> &[u8];

    fn area_mut(&mut self) -> &mut [u8];

    unsafe fn cast_mut_maybe<T>(&mut self) -> &mut core::mem::MaybeUninit<T> {
        let (_, array, _) = unsafe { self.area_mut().align_to_mut::<core::mem::MaybeUninit<T>>() };

        if array.is_empty() {
            panic!("work area is not properly aligned for the target type");
        }

        &mut array[0]
    }

    unsafe fn cast<T>(&self) -> &T {
        let (_, array, _) = unsafe { self.area().align_to::<T>() };

        if array.is_empty() {
            panic!("work area is not properly aligned for the target type");
        }

        &array[0]
    }

    unsafe fn cast_mut<T>(&mut self) -> &mut T {
        let t = self.cast_mut_maybe();

        unsafe { t.assume_init_mut() }
    }
}

impl WorkArea for [u8] {
    fn area(&self) -> &[u8] {
        self
    }

    fn area_mut(&mut self) -> &mut [u8] {
        self
    }
}
