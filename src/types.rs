use std::os::raw::c_void;

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
    pub peb_ptr: *const u64,
    pub peb_data: PEB,
}
pub trait CastPointers<T, U> {
    #[inline]
    fn as_ptr(&self) -> *const U {
        self as *const _ as *const _
    }

    #[inline]
    fn as_mut_ptr(&mut self) -> *mut U {
        self as *mut _ as *mut _
    }
}

impl CastPointers<PEB, c_void> for PEB {}
impl CastPointers<PEB_LDR_DATA, c_void> for PEB_LDR_DATA {}

impl CastPointers<u64, u64> for u64 {
    fn as_ptr(&self) -> *const u64 {
        *self as *const _
    }

    fn as_mut_ptr(&mut self) -> *mut u64 {
        *self as *mut _
    }
}
