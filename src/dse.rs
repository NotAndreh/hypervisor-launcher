// A lot of this code has been ported from EfiDSEFix (https://github.com/Mattiwatti/EfiGuard)

use iced_x86::{Decoder, DecoderOptions, Instruction};

use crate::ntapi;
use crate::pe::MappedImage;

use std::ffi::c_void;
use std::path::PathBuf;

/// Locate g_CiOptions kernel address and write a new value to it.
/// Returns the previous value of g_CiOptions/g_CiEnabled
pub fn adjust_ci_options(new_value: u32, read_only: bool) -> Result<u32, String> {
    // Find CI variable address
    let ci_addr = find_ci_options_variable()?;
    println!("[*] CI variable at kernel address: 0x{:016X}", ci_addr);

    // Verify EfiGuard hook is working
    test_set_variable_hook()?;

    // Determine patch size: 4 bytes on Win8+ (g_CiOptions), 1 byte on Win7 (g_CiEnabled)
    let build = ntapi::get_os_build_number();
    let patch_size: u32 = if build >= 9200 { 4 } else { 1 };

    // Set up backdoor data
    let mut data = ntapi::EfiGuardBackdoorData::new();
    data.cookie_value = ntapi::EFIGUARD_BACKDOOR_COOKIE_VALUE;
    data.kernel_address = ci_addr as *mut c_void;

    if patch_size == 4 {
        unsafe { data.u.s.set_dword(new_value) };
    } else {
        unsafe { data.u.s.set_byte(new_value as u8) };
    }
    data.size = patch_size;
    data.read_only = if read_only { 1 } else { 0 };

    ntapi::efi_set_variable(&mut data)?;

    // Extract the old value
    let old_value = if patch_size == 4 {
        unsafe { data.u.s.get_dword() }
    } else {
        unsafe { data.u.s.get_byte() as u32 }
    };

    Ok(old_value)
}

/// Test the EfiGuard SetVariable hook by reading the MZ signature from hal.dll
fn test_set_variable_hook() -> Result<(), String> {
    // Find hal.dll kernel base
    let hal_base = ntapi::find_kernel_module("hal.dll")?;

    let mut data = ntapi::EfiGuardBackdoorData::new();
    data.cookie_value = ntapi::EFIGUARD_BACKDOOR_COOKIE_VALUE;
    data.kernel_address = hal_base as *mut c_void;
    data.u.qword = u64::MAX; // bogus value to verify write-back
    data.size = 2; // sizeof(u16)
    data.read_only = 1;

    ntapi::efi_set_variable(&mut data)?;

    if unsafe { data.u.qword } == u64::MAX {
        // Clean up by deleting the variable from NVRAM
        // (we actually wrote it since the hook wasn't active)
        return Err(
            "EFI SetVariable() did not return data. EfiGuard DXE driver not loaded or malfunctioning.".into()
        );
    }

    // Check for "MZ" signature
    let mz = unsafe { data.u.s.get_word() };
    if mz != 0x5A4D {
        return Err(format!(
            "Unexpected data from hal.dll read. Expected MZ (0x5A4D), got 0x{:04X}",
            mz
        ));
    }

    println!("[+] EfiGuard SetVariable hook verified (hal.dll MZ check passed).");
    Ok(())
}

/// Find the kernel address of g_CiOptions (Win8+) or g_CiEnabled (Win7)
fn find_ci_options_variable() -> Result<u64, String> {
    let build = ntapi::get_os_build_number();

    if build >= 9200 {
        // Windows 8+: CI.dll!g_CiOptions
        let ci_base = ntapi::find_kernel_module("CI.dll")?;
        println!("[*] CI.dll kernel base: 0x{:016X}", ci_base);

        let system_root = get_system_root();
        let ci_path = PathBuf::from(&system_root).join("System32").join("CI.dll");
        let mapped = MappedImage::map(&ci_path)?;

        find_ci_options(&mapped, ci_base)
    } else {
        // Windows 7: ntoskrnl.exe!g_CiEnabled
        let kernel_base = ntapi::find_kernel_module("ntoskrnl.exe")?;
        println!("[*] ntoskrnl.exe kernel base: 0x{:016X}", kernel_base);

        let system_root = get_system_root();
        let ntoskrnl_path = PathBuf::from(&system_root)
            .join("System32")
            .join("ntoskrnl.exe");
        let mapped = MappedImage::map(&ntoskrnl_path)?;

        find_ci_enabled(&mapped, kernel_base)
    }
}

/// Find g_CiOptions in a mapped CI.dll by disassembling CiInitialize -> CipInitialize
fn find_ci_options(mapped: &MappedImage, ci_dll_base: u64) -> Result<u64, String> {
    let ci_initialize = mapped
        .get_export("CiInitialize")
        .ok_or("CiInitialize export not found in CI.dll")?;

    let ci_init_rva = ci_initialize as usize - mapped.base as usize;
    println!("[*] CiInitialize RVA: 0x{:X}", ci_init_rva);

    // Dump section info for debugging
    for section in mapped.sections() {
        let name = std::str::from_utf8(&section.Name)
            .unwrap_or("")
            .trim_end_matches('\0');
        println!(
            "    Section: {:8} VA: 0x{:08X} Size: 0x{:08X}",
            name, section.VirtualAddress, unsafe { section.Misc.VirtualSize }
        );
    }

    let build = ntapi::get_os_build_number();
    println!("[*] OS Build: {}", build);

    // Walk instructions in CiInitialize to find the CALL/JMP to CipInitialize
    let mut offset: usize = 0;
    let mut relative: i32 = 0;
    let mut insn_len: usize = 0;

    let code_slice = unsafe {
        let max_len = mapped.size - (ci_initialize as usize - mapped.base as usize);
        std::slice::from_raw_parts(ci_initialize, max_len.min(512))
    };

    if build >= 16299 {
        // Windows 10 1709+: find a CALL (E8) whose target is in PAGE section
        // We skip calls whose targets are NOT in PAGE (e.g. __security_init_cookie in INIT).
        let mut call_count: u32 = 0;
        let mut found = false;
        while offset < 256 && offset < code_slice.len() {
            let insn = match decode_insn(&code_slice[offset..]) {
                Some(len) => len,
                None => {
                    println!("[!] Decoder error at CiInitialize+0x{:X}", offset);
                    break;
                }
            };

            if insn == 5 && code_slice[offset] == 0xE8 {
                call_count += 1;
                let rel = i32::from_le_bytes([
                    code_slice[offset + 1],
                    code_slice[offset + 2],
                    code_slice[offset + 3],
                    code_slice[offset + 4],
                ]);

                let call_target = unsafe {
                    ci_initialize.add(offset + 5).offset(rel as isize)
                };
                let target_addr = call_target as usize;
                let base_addr = mapped.base as usize;

                // Bounds check: only consider calls within the mapped image
                if target_addr >= base_addr && target_addr < base_addr + mapped.size {
                    let target_rva = target_addr - base_addr;
                    let in_page = mapped.address_in_section(call_target, "PAGE");
                    println!(
                        "[*] CiInitialize+0x{:02X}: CALL #{} -> RVA 0x{:X} (in PAGE: {})",
                        offset, call_count, target_rva, in_page
                    );

                    if in_page {
                        relative = rel;
                        insn_len = insn;
                        found = true;
                        break;
                    }
                } else {
                    println!(
                        "[*] CiInitialize+0x{:02X}: CALL #{} -> 0x{:X} (out of image, skipping)",
                        offset, call_count, target_addr
                    );
                }
            }

            offset += insn;
        }

        if !found {
            // Fallback: try JMP rel32 (E9) as well
            offset = 0;
            while offset < 256 && offset < code_slice.len() {
                let insn = match decode_insn(&code_slice[offset..]) {
                    Some(len) => len,
                    None => {
                        println!("[!] Decoder error at CiInitialize+0x{:X}", offset);
                        break;
                    }
                };
                if insn == 5 && code_slice[offset] == 0xE9 {
                    let rel = i32::from_le_bytes([
                        code_slice[offset + 1],
                        code_slice[offset + 2],
                        code_slice[offset + 3],
                        code_slice[offset + 4],
                    ]);
                    relative = rel;
                    insn_len = insn;
                    println!("[*] CiInitialize+0x{:02X}: JMP rel32 -> fallback", offset);
                    break;
                }
                offset += insn;
            }
        }
    } else {
        // Older builds: find JMP rel32 (E9)
        while offset < 256 && offset < code_slice.len() {
            let insn = match decode_insn(&code_slice[offset..]) {
                Some(len) => len,
                None => {
                    println!("[!] Decoder error at CiInitialize+0x{:X}", offset);
                    break;
                }
            };

            if insn == 5 && code_slice[offset] == 0xE9 {
                relative = i32::from_le_bytes([
                    code_slice[offset + 1],
                    code_slice[offset + 2],
                    code_slice[offset + 3],
                    code_slice[offset + 4],
                ]);
                insn_len = insn;
                break;
            }

            offset += insn;
        }
    }

    if relative == 0 {
        return Err("Failed to find CipInitialize call/jump".into());
    }

    let cip_initialize = unsafe { ci_initialize.add(offset + insn_len).offset(relative as isize) };

    // Bounds check: ensure cip_initialize is within the mapped image
    let cip_addr = cip_initialize as usize;
    let base_addr = mapped.base as usize;
    if cip_addr < base_addr || cip_addr >= base_addr + mapped.size {
        return Err(format!(
            "CipInitialize address 0x{:X} is outside mapped image [0x{:X}..0x{:X}]",
            cip_addr, base_addr, base_addr + mapped.size
        ));
    }

    let cip_rva = cip_addr - base_addr;
    println!("[*] CipInitialize candidate at RVA 0x{:X}", cip_rva);

    // On newer Windows builds, CipInitialize may be in PAGE or PAGECIOP or similar
    let in_page = mapped.address_in_section(cip_initialize, "PAGE");
    if !in_page {
        let mut found_section = "UNKNOWN";
        for section in mapped.sections() {
            let sec_start = section.VirtualAddress as usize;
            let sec_end = sec_start + unsafe { section.Misc.VirtualSize } as usize;
            if cip_rva >= sec_start && cip_rva < sec_end {
                found_section = std::str::from_utf8(&section.Name)
                    .unwrap_or("???")
                    .trim_end_matches('\0');
                break;
            }
        }
        println!(
            "[!] CipInitialize RVA 0x{:X} is in section '{}', not PAGE. Proceeding anyway.",
            cip_rva, found_section
        );
    }

    // Now scan CipInitialize for: mov [rip+disp32], ecx (89 0D xx xx xx xx)
    let remaining = mapped.size - cip_rva;
    let cip_code = unsafe {
        std::slice::from_raw_parts(cip_initialize, remaining.min(512))
    };

    let mut ci_offset: usize = 0;
    let mut ci_relative: i32 = 0;
    let mut ci_insn_len: usize = 0;

    while ci_offset < 256 && ci_offset < cip_code.len().saturating_sub(6) {
        let insn = match decode_insn(&cip_code[ci_offset..]) {
            Some(len) => len,
            None => {
                println!("[!] Decoder error at CipInitialize+0x{:X}", ci_offset);
                break;
            }
        };

        // Look for 89 0D (MOV [rip+disp32], ecx)
        if insn == 6
            && cip_code[ci_offset] == 0x89
            && cip_code[ci_offset + 1] == 0x0D
        {
            ci_relative = i32::from_le_bytes([
                cip_code[ci_offset + 2],
                cip_code[ci_offset + 3],
                cip_code[ci_offset + 4],
                cip_code[ci_offset + 5],
            ]);
            ci_insn_len = insn;
            break;
        }

        ci_offset += insn;
    }

    if ci_relative == 0 {
        return Err("Failed to find mov [g_CiOptions], ecx instruction".into());
    }

    let mapped_ci_options = unsafe {
        cip_initialize
            .add(ci_offset + ci_insn_len)
            .offset(ci_relative as isize)
    };

    // Verify the target is in .data or CiPolicy section
    if !mapped.address_in_section(mapped_ci_options, ".data")
        && !mapped.address_in_section(mapped_ci_options, "CiPolicy")
    {
        return Err("g_CiOptions target not in .data or CiPolicy section".into());
    }

    // Compute kernel address
    let mapped_offset = mapped_ci_options as u64 - mapped.base as u64;
    let kernel_address = ci_dll_base + mapped_offset;

    Ok(kernel_address)
}

/// Find g_CiEnabled in a mapped ntoskrnl.exe (Win7 fallback).
fn find_ci_enabled(mapped: &MappedImage, kernel_base: u64) -> Result<u64, String> {
    let data = mapped.as_slice();

    for i in 0..data.len().saturating_sub(8) {
        let dword = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        if dword == 0x1d8806eb {
            let relative = i32::from_le_bytes([
                data[i + 4],
                data[i + 5],
                data[i + 6],
                data[i + 7],
            ]);
            let address = kernel_base
                .wrapping_add(i as u64)
                .wrapping_add(8)
                .wrapping_add(relative as u64);
            return Ok(address);
        }
    }

    Err("g_CiEnabled pattern not found in ntoskrnl.exe".into())
}

fn get_system_root() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string())
}

pub fn decode_insn(code: &[u8]) -> Option<usize> {
    if code.is_empty() {
        return None;
    }

    let mut decoder = Decoder::with_ip(64, code, 0, DecoderOptions::NONE);
    let mut instruction = Instruction::default();
    decoder.decode_out(&mut instruction);

    if instruction.is_invalid() {
        return None;
    }

    Some(instruction.len())
}
