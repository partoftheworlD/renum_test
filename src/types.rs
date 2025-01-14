use std::{
    os::raw::c_void,
    ptr::{from_mut, from_ref}, usize,
};

use windows::Win32::System::{
    Threading::{PEB, PEB_LDR_DATA},
    WindowsProgramming::SYSTEM_PROCESS_INFORMATION,
};

//SYSTEM_INFORMATION_CLASS enum
pub enum SysInfoClass {
    ProcessBasicInformation,
    SysProcessList = 5,
}

#[repr(C)]
pub struct ProcessThings {
    pub info: SYSTEM_PROCESS_INFORMATION,
    pub name: String,
    pub threads: u32,
    pub handles: u32,
    pub id: u32,
    pub arch: bool,
    pub peb_ptr: *const usize,
    pub peb_data: PEB,
}
pub trait CastPointers<U> {
    #[inline]
    fn as_ptr(&self) -> *const U {
        from_ref(self).cast()
    }

    #[inline]
    fn as_mut_ptr(&mut self) -> *mut U {
        from_mut(self).cast()
    }
}

impl<T> CastPointers<c_void> for T {}

impl CastPointers<usize> for usize {
    fn as_ptr(&self) -> *const usize {
        *self as *const _
    }

    fn as_mut_ptr(&mut self) -> *mut usize {
        *self as *mut _
    }
}
