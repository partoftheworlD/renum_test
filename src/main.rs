use windows::{
    Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS},
    Win32::System::WindowsProgramming::SYSTEM_PROCESS_INFORMATION,
};

//SYSTEM_INFORMATION_CLASS enum
enum Sic {
    SysProcessList = 5,
}
#[repr(C)]
struct ProcessThings {
    info: SYSTEM_PROCESS_INFORMATION,
    name: String,
    threads: u32,
    handles: u32,
    pid: u32,
}

fn read_pwstr(process: &SYSTEM_PROCESS_INFORMATION) -> String {
    if process.ImageName.Buffer.is_null() {
        return String::new();
    }
    String::from_utf16_lossy(unsafe { process.ImageName.Buffer.as_wide() })
}

fn get_process(process_name: &str) -> Vec<ProcessThings> {
    let mut process_list: Vec<ProcessThings> = Vec::new();
    static SYSPROCESSINFO: SYSTEM_INFORMATION_CLASS =
        SYSTEM_INFORMATION_CLASS(Sic::SysProcessList as i32);
    let mut buffer_size = 1024 * 1024;
    let mut process_information = Vec::<u8>::with_capacity(buffer_size.try_into().unwrap());
    let _ = unsafe {
        NtQuerySystemInformation(
            SYSPROCESSINFO,
            process_information.as_mut_ptr().cast(),
            buffer_size,
            &mut buffer_size,
        )
    };
    let mut count = 0u32;

    loop {
        let process: SYSTEM_PROCESS_INFORMATION = unsafe {
            *(process_information
                .as_ptr()
                .offset(count.try_into().unwrap())
                .cast())
        };
        if !process.ImageName.Buffer.is_null() {
            let name = read_pwstr(&process);
            if name.to_ascii_lowercase() == process_name {
                process_list.push(ProcessThings {
                    info: process,
                    name,
                    threads: process.NumberOfThreads,
                    handles: process.HandleCount,
                    pid: process.UniqueProcessId.0 as u32,
                });
            }
        }

        let next = process.NextEntryOffset;
        if next == 0 {
            break;
        }
        count += next;
    }
    process_list
}

fn main() {
    let plist = get_process("gta5.exe");
    println!("Total: {:?}", plist.len());
    for process in plist {
        println!(
            "Process ID: 0x{:04X} Name: {} Threads: {:04} Handles: {:04}",
            process.pid, process.name, process.threads, process.handles
        );
    }
}
