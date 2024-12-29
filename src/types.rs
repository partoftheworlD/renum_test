use windows::Win32::System::WindowsProgramming::SYSTEM_PROCESS_INFORMATION;

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
    pub peb: *mut u64,
    pub arch: bool,
}
pub trait CastPointers {
    fn as_mut_ptr<T>(&mut self) -> *mut T;
    fn as_ptr<T>(&self) -> *const T;
}
impl CastPointers for u64 {
    #[inline]
    fn as_mut_ptr<T>(&mut self) -> *mut T {
        *self as *mut T
    }
    #[inline]
    fn as_ptr<T>(&self) -> *const T {
        *self as *const T
    }
}
