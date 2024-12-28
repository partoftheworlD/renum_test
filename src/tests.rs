use windows::Win32::System::WindowsProgramming::SYSTEM_PROCESS_INFORMATION;

use crate::{errors::Errors, get_process, read_pwstr};

#[test]
fn found_process() {
    assert!(get_process("svchost.exe").unwrap().len() >= 1)
}

#[test]
fn not_found_process() {
    assert_eq!(get_process("").err().unwrap(), Errors::ProcessNotFound)
}

#[test]
fn read_pwstr_empty_buffer() {
    let spi: SYSTEM_PROCESS_INFORMATION = Default::default();
    assert_eq!(
        read_pwstr(&spi).err().unwrap(),
        Errors::EmptyBuffer("process.ImageName.Buffer is empty")
    )
}