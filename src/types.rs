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
