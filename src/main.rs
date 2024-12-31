use windows::{
    Wdk::System::{
        SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS},
        Threading::{NtQueryInformationProcess, PROCESSINFOCLASS},
    },
    Win32::{
        Foundation::BOOL,
        System::{
            Diagnostics::Debug::ReadProcessMemory,
            Threading::{
                IsWow64Process, OpenProcess, PEB, PEB_LDR_DATA, PROCESS_BASIC_INFORMATION,
                PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
            },
            WindowsProgramming::SYSTEM_PROCESS_INFORMATION,
        },
    },
};

use std::{mem, ptr::null_mut};

mod errors;
mod tests;
use errors::Errors;
mod types;
use types::{CastPointers, ProcessThings, SysInfoClass};

fn read_pwstr(process: &SYSTEM_PROCESS_INFORMATION) -> Result<String, Errors> {
    if process.ImageName.Buffer.is_null() {
        return Err(Errors::EmptyBuffer("process.ImageName.Buffer is empty"));
    }
    Ok(String::from_utf16_lossy(unsafe {
        process.ImageName.Buffer.as_wide()
    }))
}

fn get_peb_ldr(process_list: &mut Vec<ProcessThings>) {
    static BASICPROCESSINFO: PROCESSINFOCLASS =
        PROCESSINFOCLASS(SysInfoClass::ProcessBasicInformation as i32);

    let buffer_size = size_of::<PROCESS_BASIC_INFORMATION>();
    let mut process_basic_info = Vec::<u8>::with_capacity(buffer_size);
    let mut arch = BOOL(0);

    for process in process_list {
        let handle = unsafe {
            match OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false,
                process.id,
            ) {
                Ok(handle) => handle,
                Err(why) => panic!("{}", why),
            }
        };

        let _ = unsafe { IsWow64Process(handle, &mut arch) };
        let _ntstatus = unsafe {
            NtQueryInformationProcess(
                handle,
                BASICPROCESSINFO,
                process_basic_info.as_mut_ptr().cast(),
                buffer_size.try_into().unwrap(),
                null_mut(),
            )
        };
        // SAFETY: Simple cast *(PROCESS_BASIC_INFORMATION*)process_basic_info
        let proc_info: PROCESS_BASIC_INFORMATION = unsafe { *(process_basic_info.as_ptr().cast()) };

        if arch.as_bool() {
            process.peb_ptr = (proc_info.PebBaseAddress as u64 + 0x1000).as_mut_ptr();
            process.arch = false;
        } else {
            process.peb_ptr = (proc_info.PebBaseAddress as u64).as_mut_ptr();
            process.arch = true;
        }

        let mut ptr = process.peb_ptr as *const _;
        let mut data: PEB = unsafe { mem::zeroed() };
        unsafe {
            let _ = ReadProcessMemory(
                handle,
                ptr,
                data.as_mut_ptr(),
                size_of_val(&data),
                Some(&mut 0),
            );
        };
        process.peb_data = data;

        // Get LDR
        // TODO: Add LDR support for x86, currently only x64 pointer is correct
        ptr = process.peb_data.Ldr as *const _;
        let mut data: PEB_LDR_DATA = unsafe { mem::zeroed() };
        unsafe {
            let _ = ReadProcessMemory(
                handle,
                ptr,
                data.as_mut_ptr(),
                size_of_val(&data),
                Some(&mut 0),
            );
        };
    }
}

fn get_process(process_name: &str) -> Result<Vec<ProcessThings>, Errors> {
    static SYSPROCESSINFO: SYSTEM_INFORMATION_CLASS =
        SYSTEM_INFORMATION_CLASS(SysInfoClass::SysProcessList as i32);

    if process_name.is_empty() {
        return Err(Errors::ProcessNotFound);
    }

    let mut process_list: Vec<ProcessThings> = Vec::new();
    let buffer_size = 1024 * 1024;
    let mut process_information = Vec::<u8>::with_capacity(buffer_size.try_into().unwrap());
    let mut count = 0u32;

    let _ = unsafe {
        NtQuerySystemInformation(
            SYSPROCESSINFO,
            process_information.as_mut_ptr().cast(),
            buffer_size,
            null_mut(),
        )
    };

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
                    peb_ptr: null_mut(),
                    arch: true,
                    peb_data: PEB::default(),
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
    let mut plist = match get_process("gta5.exe") {
        Ok(plist) => plist,
        Err(why) => panic!("{}", why),
    };

    get_peb_ldr(&mut plist);

    for process in &plist {
        let arch = if process.arch { "x64" } else { "x32" };
        println!(
            "{} Process ID: 0x{:04X} ({:05}) Name: {} Threads: {:04} Handles: {:04} PEB: 0x{:010X} LDR: 0x{:X}",
            arch,
            process.id,
            process.id,
            process.name,
            process.threads,
            process.handles,
            process.peb_ptr as u64,
            process.peb_data.Ldr as u64
        );
    }
    println!("Total: {:?}", plist.len());
}
