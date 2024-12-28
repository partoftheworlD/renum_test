use windows::{
    Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS},
    Win32::System::WindowsProgramming::SYSTEM_PROCESS_INFORMATION,
};

mod errors;
use errors::Errors;
mod types;
use types::{ProcessThings, Sic};

fn read_pwstr(process: &SYSTEM_PROCESS_INFORMATION) -> Result<String, Errors> {
    if process.ImageName.Buffer.is_null() {
        return Err(Errors::EmptyBuffer("process.ImageName.Buffer is empty"));
    }
    Ok(String::from_utf16_lossy(unsafe {
        process.ImageName.Buffer.as_wide()
    }))
}

fn get_process(process_name: &str) -> Result<Vec<ProcessThings>, Errors> {
    let mut process_list: Vec<ProcessThings> = Vec::new();
    #[allow(clippy::items_after_statements)]
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
            let name = match read_pwstr(&process) {
                Ok(process_name) => process_name,
                Err(why) => panic!("{}", why),
            };
            if name.to_ascii_lowercase() == process_name {
                process_list.push(ProcessThings {
                    info: process,
                    name,
                    threads: process.NumberOfThreads,
                    handles: process.HandleCount,
                    id: process.UniqueProcessId.0 as u32,
                });
            }
        }

        let next = process.NextEntryOffset;
        if next == 0 {
            break;
        }
        count += next;
    }

    if process_list.is_empty() {
        Err(Errors::ProcessNotFound)
    } else {
        Ok(process_list)
    }
}

fn main() {
    let plist = match get_process("gta5.exe") {
        Ok(plist) => plist,
        Err(why) => panic!("{}", why),
    };
    for process in &plist {
        println!(
            "Process ID: 0x{:04X} Name: {} Threads: {:04} Handles: {:04}",
            process.id, process.name, process.threads, process.handles
        );
    }
    println!("Total: {:?}", plist.len());
}
