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
pub trait CastPointers {
    type Item;
    fn as_mut_ptr(&mut self) -> *mut Self::Item;
    fn as_ptr(&self) -> *const Self::Item;
}
impl CastPointers for u64 {
    type Item = u64;
    #[inline]
    fn as_mut_ptr(&mut self) -> *mut Self::Item {
        *self as *mut Self::Item
    }
    #[inline]
    fn as_ptr(&self) -> *const Self::Item {
        *self as *const Self::Item
    }
}

impl CastPointers for PEB {
    type Item = c_void;
    #[inline]
    fn as_mut_ptr(&mut self) -> *mut Self::Item {
        self as *mut _ as *mut _
    }
    #[inline]
    fn as_ptr(&self) -> *const Self::Item {
        self as *const _ as *const _
    }
}

impl CastPointers for PEB_LDR_DATA {
    type Item = c_void;
    #[inline]
    fn as_mut_ptr(&mut self) -> *mut Self::Item {
        self as *mut _ as *mut _
    }
    #[inline]
    fn as_ptr(&self) -> *const Self::Item {
        self as *const _ as *const _
    }
}
