use windows::{
    Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS},
    Win32::System::WindowsProgramming::SYSTEM_PROCESS_INFORMATION,
};

fn read_pwstr(pwstr: *const u16) -> String {
    let mut len = 0;
    while unsafe { *pwstr.offset(len) } != 0 {
        len += 1;
    }
    let slice = unsafe { std::slice::from_raw_parts(pwstr, len as usize) };
    String::from_utf16_lossy(slice)
}

fn main() {
    const SYSPROCESSINFO: SYSTEM_INFORMATION_CLASS = SYSTEM_INFORMATION_CLASS(0x5);
    let mut buffer_size = 1024 * 1024;
    let mut process_information = Vec::<u8>::with_capacity(buffer_size as usize);

    unsafe {
        let _ = NtQuerySystemInformation(
            SYSPROCESSINFO,
            process_information.as_mut_ptr().cast(),
            buffer_size,
            &mut buffer_size,
        );
        let mut process_count = 0;
        let mut count = 0;
        loop {
            let process = *(process_information
                .as_ptr()
                .offset(count)
                .cast::<SYSTEM_PROCESS_INFORMATION>());

            if !process.ImageName.Buffer.is_null() {
                let pwstr_string = process.ImageName.Buffer;
                let process_name = read_pwstr(pwstr_string.0);
                println!(
                    "Process name: {process_name:?} pID: {:X?}", process.UniqueProcessId.0
                );
            }
            let next = process.NextEntryOffset;
            if next == 0 {
                break;
            }
            process_count += 1;
            count += next as isize;
        }
        println!("Total processes: {process_count:?}",)
    };
}
