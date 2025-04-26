use windows::{
    core::BOOL,
    Wdk::System::{
        SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS},
        Threading::{NtQueryInformationProcess, PROCESSINFOCLASS},
    },
    Win32::{
        Foundation::HANDLE,
        System::{
            Diagnostics::Debug::ReadProcessMemory,
            Threading::{
                IsWow64Process, OpenProcess, PEB, PROCESS_BASIC_INFORMATION,
                PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
            },
            WindowsProgramming::SYSTEM_PROCESS_INFORMATION,
        },
    },
};

use std::{ffi::c_void, ptr::null_mut};

mod errors;
mod tests;
use errors::Errors;
mod types;
use types::{Arch, CastPointers, ProcessThings, SysInfoClass};

fn read_pwstr(process: &SYSTEM_PROCESS_INFORMATION) -> Result<String, Errors> {
    if process.ImageName.Buffer.is_null() {
        return Err(Errors::EmptyBuffer("process.ImageName.Buffer is empty"));
    }
    Ok(String::from_utf16_lossy(unsafe {
        process.ImageName.Buffer.as_wide()
    }))
}

fn read_memory<T>(handle: &HANDLE, ptr: *const c_void, buffer: &mut T)
where
    T: CastPointers<c_void>,
{
    unsafe {
        match ReadProcessMemory(
            *handle,
            ptr,
            buffer.as_mut_ptr().cast(),
            size_of_val(buffer),
            Some(&mut 0),
        ) {
            Ok(()) => (),
            Err(why) => panic!("{why}"),
        }
    };
}

fn get_process_information(
    handle: &HANDLE,
    infoclass: &PROCESSINFOCLASS,
    buffer: &mut Vec<u8>,
    buffer_size: usize,
) {
    let _ntstatus = unsafe {
        NtQueryInformationProcess(
            *handle,
            *infoclass,
            buffer.as_mut_ptr().cast(),
            buffer_size.try_into().unwrap(),
            null_mut(),
        )
    };
}

fn get_system_information(
    infoclass: &SYSTEM_INFORMATION_CLASS,
    buffer: &mut Vec<u8>,
    buffer_size: u32,
) {
    let _ntstatus = unsafe {
        NtQuerySystemInformation(
            *infoclass,
            buffer.as_mut_ptr().cast(),
            buffer_size,
            null_mut(),
        )
    };
}

fn get_peb_ldr(process_list: &mut Vec<ProcessThings>) {
    const BASICPROCESSINFO: PROCESSINFOCLASS =
        PROCESSINFOCLASS(SysInfoClass::ProcessBasicInformation as i32);

    const BUFFER_SIZE: usize = size_of::<PROCESS_BASIC_INFORMATION>();
    let mut process_basic_info = Vec::<u8>::with_capacity(BUFFER_SIZE);
    let mut arch = BOOL(0);

    for process in process_list {
        let handle = unsafe {
            match OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                false,
                process.id,
            ) {
                Ok(handle) => handle,
                Err(why) => panic!("{why}"),
            }
        };

        let _ = unsafe { IsWow64Process(handle, &mut arch) };

        get_process_information(
            &handle,
            &BASICPROCESSINFO,
            &mut process_basic_info,
            BUFFER_SIZE,
        );

        // SAFETY: Simple cast *(PROCESS_BASIC_INFORMATION*)process_basic_info
        let proc_info: PROCESS_BASIC_INFORMATION = unsafe { *(process_basic_info.as_ptr().cast()) };

        if arch.as_bool() {
            process.peb_ptr = (proc_info.PebBaseAddress as usize + 0x1000).as_mut_ptr();
            process.arch = Arch::X86;
        } else {
            process.peb_ptr = (proc_info.PebBaseAddress as usize).as_mut_ptr();
            process.arch = Arch::X64;
        }

        let ptr = process.peb_ptr.cast();
        read_memory(&handle, ptr, &mut process.peb_data);

        /*
        Get LDR
        TODO: Add LDR support for x86, currently only x64 pointer is correct
        let ptr = data.Ldr as _;
        let mut data: PEB_LDR_DATA = unsafe { mem::zeroed() };
        read_memory::<PEB_LDR_DATA>(&handle, ptr, &mut data);
        */
    }
}

fn get_process(process_name: &str) -> Result<Vec<ProcessThings>, Errors> {
    const SYSPROCESSINFO: SYSTEM_INFORMATION_CLASS =
        SYSTEM_INFORMATION_CLASS(SysInfoClass::SysProcessList as i32);

    if process_name.is_empty() {
        return Err(Errors::ProcessNotFound);
    }

    let mut process_list: Vec<ProcessThings> = Vec::new();
    const BUFFER_SIZE: usize = 1024 * 1024;
    let mut process_information = Vec::<u8>::with_capacity(BUFFER_SIZE);
    let mut count = 0u32;

    get_system_information(
        &SYSPROCESSINFO,
        &mut process_information,
        BUFFER_SIZE.try_into().unwrap(),
    );

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
                Err(why) => panic!("{why}"),
            };
            if name.to_ascii_lowercase() == process_name {
                process_list.push(ProcessThings {
                    info: process,
                    name,
                    threads: process.NumberOfThreads,
                    handles: process.HandleCount,
                    id: process.UniqueProcessId.0 as u32,
                    peb_ptr: null_mut(),
                    arch: Arch::X64,
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
        Err(why) => panic!("{why}"),
    };

    get_peb_ldr(&mut plist);

    for process in &plist {
        let arch = match process.arch {
            Arch::X86 => "x32",
            Arch::X64 => "x64",
        };

        let pid = process.id;
        println!(
            "{} Process ID: 0x{:04X} ({:05}) Name: {} Threads: {:04} Handles: {:04} PEB: 0x{:X} LDR: 0x{:X}",
            arch,
            pid,
            pid,
            process.name,
            process.threads,
            process.handles,
            process.peb_ptr as usize,
            process.peb_data.Ldr as usize
        );
    }
    println!("Total: {:?}", plist.len());
}
