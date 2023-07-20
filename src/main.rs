use ntapi::ntldr::LDR_DATA_TABLE_ENTRY;
use ntapi::ntpebteb::PEB;
use ntapi::ntrtl::{RtlEnterCriticalSection, RtlInitUnicodeString, RtlLeaveCriticalSection};
use ntapi::winapi::shared::ntdef::UNICODE_STRING;

use std::arch::asm;
use std::env;

/// Gets a pointer to the Thread Environment Block (TEB)
#[cfg(target_arch = "x86")]
pub unsafe fn get_teb() -> *mut ntapi::ntpebteb::TEB {
    let teb: *mut ntapi::ntpebteb::TEB;
    asm!("mov {teb}, fs:[0x18]", teb = out(reg) teb);
    teb
}

/// Get a pointer to the Thread Environment Block (TEB)
#[cfg(target_arch = "x86_64")]
pub unsafe fn get_teb() -> *mut ntapi::ntpebteb::TEB {
    let teb: *mut ntapi::ntpebteb::TEB;
    asm!("mov {teb}, gs:[0x30]", teb = out(reg) teb);
    teb
}

/// Get a pointer to the Process Environment Block (PEB)
pub unsafe fn get_peb() -> *mut PEB {
    let teb = get_teb();
    let peb = (*teb).ProcessEnvironmentBlock;
    peb
}

// Convert the PWCH to a String
unsafe fn convert_mut_u16_to_string(ptr: *mut u16) -> String {
    if ptr.is_null() {
        return "failed".to_string();
    }

    let mut len = 0;
    while *ptr.offset(len) != 0 {
        len += 1;
    }

    let slice = std::slice::from_raw_parts(ptr, len as usize);

    let utf8_bytes: Vec<u8> = slice
        .iter()
        .flat_map(|&c| std::char::from_u32(c as u32).map(|ch| ch.to_string().into_bytes()))
        .flatten()
        .collect();

    match String::from_utf8(utf8_bytes) {
        Ok(s) => s.to_string(),
        Err(_) => "failed".to_string(),
    }
}

// Convert a String to a PWCH
unsafe fn convert_string_to_mut_u16(s: String) -> *mut u16 {
    let utf16_data: Vec<u16> = s.encode_utf16().collect();
    let len = utf16_data.len();
    let ptr =
        std::alloc::alloc(std::alloc::Layout::from_size_align(len * 2, 2).unwrap()) as *mut u16;

    std::ptr::copy_nonoverlapping(utf16_data.as_ptr(), ptr, len);

    *ptr.add(len) = 0;

    ptr
}

fn main() {
    unsafe {
        let peb = get_peb();

        let windows_explorer = convert_string_to_mut_u16("C:\\Windows\\explorer.exe".to_string());
        let explorer = convert_string_to_mut_u16("explorer.exe".to_string());

        println!("Masquerading ImagePathName and CommandLine");

        RtlInitUnicodeString(&mut (*(*peb).ProcessParameters).ImagePathName as *mut UNICODE_STRING, windows_explorer);
        RtlInitUnicodeString(&mut (*(*peb).ProcessParameters).CommandLine as *mut UNICODE_STRING, windows_explorer);

        println!("Preparing to masquerade FullDllName and BaseDllName");

        RtlEnterCriticalSection((*peb).FastPebLock);

        let mut module_list = (*(*peb).Ldr).InLoadOrderModuleList.Flink as *mut LDR_DATA_TABLE_ENTRY;
        println!("Traversing all modules");
        while !(*module_list).DllBase.is_null() {
            let current_exe_path = get_current_exe();
            let utf8_name = convert_mut_u16_to_string((*module_list).FullDllName.Buffer);

            if utf8_name == current_exe_path {
                println!("Masquerading FullDllName and BaseDllName");
                RtlInitUnicodeString(&mut (*module_list).FullDllName as *mut UNICODE_STRING, windows_explorer);
                RtlInitUnicodeString(&mut (*module_list).BaseDllName as *mut UNICODE_STRING, explorer);
            }

            module_list = (*module_list).InLoadOrderLinks.Flink as *mut LDR_DATA_TABLE_ENTRY;
        }

        println!("Masqueraded PEB");
        RtlLeaveCriticalSection((*peb).FastPebLock);
    }
}

fn get_current_exe() -> String {
    match env::current_exe() {
        Ok(exe_path) => exe_path.display().to_string(),
        Err(_) => return "failed".to_string(),
    }
}
