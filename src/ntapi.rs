// A lot of this code has been ported from EfiDSEFix (https://github.com/Mattiwatti/EfiGuard)

use std::ffi::c_void;
use std::mem;

use windows::Wdk::System::SystemServices::{SE_DEBUG_PRIVILEGE, SE_SYSTEM_ENVIRONMENT_PRIVILEGE};
use windows::Win32::Foundation::{NTSTATUS, STATUS_INFO_LENGTH_MISMATCH, STATUS_SUCCESS, UNICODE_STRING};
use windows::core::PWSTR;

// NT constants
pub const SYSTEM_MODULE_INFORMATION: u32 = 11;

// Structures
#[repr(C)]
#[derive(Clone)]
pub struct RtlProcessModuleInformation {
    pub section: *mut c_void,
    pub mapped_base: *mut c_void,
    pub image_base: *mut c_void,
    pub image_size: u32,
    pub flags: u32,
    pub load_order_index: u16,
    pub init_order_index: u16,
    pub load_count: u16,
    pub offset_to_file_name: u16,
    pub full_path_name: [u8; 256],
}

#[repr(C)]
pub struct RtlProcessModules {
    pub number_of_modules: u32
}

#[repr(C)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

// EfiGuard backdoor protocol

/// EFI_GLOBAL_VARIABLE GUID: {8BE4DF61-93CA-11D2-AA0D-00E098032B8C}
pub const EFI_GLOBAL_VARIABLE_GUID: Guid = Guid {
    data1: 0x8BE4DF61,
    data2: 0x93CA,
    data3: 0x11D2,
    data4: [0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C],
};

/// "roodkcaBdrauGifE" – the reversed "EfiGuardBackdoor" variable name
pub const EFIGUARD_BACKDOOR_VARIABLE_NAME: &str = "roodkcaBdrauGifE";

pub const EFIGUARD_BACKDOOR_COOKIE_VALUE: u64 = 0xDEADC0DE;
pub const EFIGUARD_BACKDOOR_VARIABLE_ATTRIBUTES: u32 = 0x07; // NV | BS_ACCESS | RT_ACCESS

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EfiGuardBackdoorData {
    pub cookie_value: u64,
    pub kernel_address: *mut c_void,
    pub u: EfiGuardBackdoorUnion,
    pub size: u32,
    pub read_only: u8, // BOOLEAN
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union EfiGuardBackdoorUnion {
    pub s: EfiGuardBackdoorBitfield,
    pub qword: u64,
    pub user_buffer: *mut c_void,
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default)]
pub struct EfiGuardBackdoorBitfield(pub u64);

#[allow(dead_code)]
impl EfiGuardBackdoorBitfield {
    pub fn get_byte(&self) -> u8 {
        (self.0 & 0xFF) as u8
    }

    pub fn get_word(&self) -> u16 {
        ((self.0 >> 8) & 0xFFFF) as u16
    }

    pub fn get_dword(&self) -> u32 {
        ((self.0 >> 24) & 0xFFFFFFFF) as u32
    }

    pub fn set_byte(&mut self, val: u8) {
        self.0 = (self.0 & !0xFF) | (val as u64);
    }

    pub fn set_word(&mut self, val: u16) {
        self.0 = (self.0 & !(0xFFFF << 8)) | ((val as u64) << 8);
    }

    pub fn set_dword(&mut self, val: u32) {
        self.0 = (self.0 & !(0xFFFFFFFF << 24)) | ((val as u64) << 24);
    }
}

impl EfiGuardBackdoorData {
    pub fn new() -> Self {
        EfiGuardBackdoorData {
            cookie_value: 0,
            kernel_address: std::ptr::null_mut(),
            u: EfiGuardBackdoorUnion { qword: 0 },
            size: 0,
            read_only: 0,
        }
    }
}

pub const EFIGUARD_BACKDOOR_DATA_SIZE: u32 = mem::size_of::<EfiGuardBackdoorData>() as u32;

const SYSTEM_CODE_INTEGRITY_INFORMATION: u32 = 103;
const CODE_INTEGRITY_OPTION_TESTSIGNING: u32 = 0x00000002;

#[repr(C)]
struct SYSTEM_CODE_INTEGRITY_INFORMATION_STRUCT {
    length: u32,
    code_integrity_options: u32,
}

// External NT functions

#[link(name = "ntdll")]
unsafe extern "system" {
    pub fn RtlAdjustPrivilege(
        Privilege: i32,
        Enable: u8,      // BOOLEAN
        CurrentThread: u8, // BOOLEAN
        WasEnabled: *mut u8,
    ) -> NTSTATUS;

    pub fn NtQuerySystemInformation(
        SystemInformationClass: u32,
        SystemInformation: *mut c_void,
        SystemInformationLength: u32,
        ReturnLength: *mut u32,
    ) -> NTSTATUS;

    pub fn NtSetSystemEnvironmentValueEx(
        VariableName: *const UNICODE_STRING,
        VendorGuid: *const Guid,
        Value: *mut c_void,
        ValueLength: u32,
        Attributes: u32,
    ) -> NTSTATUS;

    pub fn RtlGetVersion(
        lpVersionInformation: *mut OsVersionInfoExW,
    ) -> NTSTATUS;
}

#[repr(C)]
pub struct OsVersionInfoExW {
    pub os_version_info_size: u32,
    pub major_version: u32,
    pub minor_version: u32,
    pub build_number: u32,
    pub platform_id: u32,
    pub csd_version: [u16; 128],
    pub service_pack_major: u16,
    pub service_pack_minor: u16,
    pub suite_mask: u16,
    pub product_type: u8,
    pub reserved: u8,
}

pub fn get_os_build_number() -> u32 {
    unsafe {
        let mut info: OsVersionInfoExW = std::mem::zeroed();
        info.os_version_info_size = std::mem::size_of::<OsVersionInfoExW>() as u32;
        let _ = RtlGetVersion(&mut info);
        info.build_number
    }
}

// Helper functions

/// Acquire SE_SYSTEM_ENVIRONMENT_PRIVILEGE and SE_DEBUG_PRIVILEGE
pub fn acquire_privileges() -> Result<(), String> {
    unsafe {
        let mut was_enabled: u8 = 0;

        let status =
            RtlAdjustPrivilege(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, 1, 0, &mut was_enabled);
        if status != STATUS_SUCCESS {
            return Err(format!(
                "Failed to acquire SE_SYSTEM_ENVIRONMENT_PRIVILEGE: 0x{:08X}",
                status.0 as u32
            ));
        }

        let status = RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, 1, 0, &mut was_enabled);
        if status != STATUS_SUCCESS {
            return Err(format!(
                "Failed to acquire SE_DEBUG_PRIVILEGE: 0x{:08X}",
                status.0 as u32
            ));
        }
    }
    Ok(())
}

/// Find the kernel-space base address of a loaded kernel module by name
pub fn find_kernel_module(module_name: &str) -> Result<u64, String> {
    unsafe {
        let mut size: u32 = 0;
        let status = NtQuerySystemInformation(
            SYSTEM_MODULE_INFORMATION, 
            std::ptr::null_mut(), 
            0, 
            &mut size
        );
        if status != STATUS_INFO_LENGTH_MISMATCH {
            return Err(format!(
                "NtQuerySystemInformation size query failed: 0x{:08X}",
                status.0 as u32
            ));
        }

        let alloc_size = (size as usize) * 2;
        let buffer = vec![0u8; alloc_size];
        let ptr = buffer.as_ptr() as *mut c_void;

        let status = NtQuerySystemInformation(
            SYSTEM_MODULE_INFORMATION,
            ptr,
            alloc_size as u32,
            std::ptr::null_mut(),
        );
        if status != STATUS_SUCCESS {
            return Err(format!(
                "NtQuerySystemInformation failed: 0x{:08X}",
                status.0 as u32
            ));
        }

        let modules = ptr as *const RtlProcessModules;
        let count = (*modules).number_of_modules;
        let first_module = (modules as *const u8)
            .add(mem::size_of::<u64>())
            as *const RtlProcessModuleInformation;

        for i in 0..count {
            let module = &*first_module.add(i as usize);
            let name_offset = module.offset_to_file_name as usize;
            let name_bytes = &module.full_path_name[name_offset..];
            let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
            let name = std::str::from_utf8(&name_bytes[..name_end]).unwrap_or("");

            if name.eq_ignore_ascii_case(module_name) {
                let base = module.image_base as u64;
                if base == 0 {
                    return Err(format!("Module '{}' has null base address", module_name));
                }
                return Ok(base);
            }
        }

        Err(format!("Module '{}' not found", module_name))
    }
}

/// Call NtSetSystemEnvironmentValueEx with the EfiGuard backdoor protocol
pub fn efi_set_variable(data: &mut EfiGuardBackdoorData) -> Result<(), String> {
    let mut name_buf: Vec<u16> = EFIGUARD_BACKDOOR_VARIABLE_NAME
        .encode_utf16().chain(std::iter::once(0)).collect();

    let name_len = ((name_buf.len() - 1) * 2) as u16;
    let max_name_len = (name_buf.len() * 2) as u16;

    let us = UNICODE_STRING {
        Length: name_len,
        MaximumLength: max_name_len,
        Buffer: PWSTR(name_buf.as_mut_ptr()),
    };

    let status = unsafe {
        NtSetSystemEnvironmentValueEx(
            &us as *const UNICODE_STRING,
            &EFI_GLOBAL_VARIABLE_GUID as *const Guid,
            data as *mut EfiGuardBackdoorData as *mut c_void,
            EFIGUARD_BACKDOOR_DATA_SIZE,
            EFIGUARD_BACKDOOR_VARIABLE_ATTRIBUTES,
        )
    };

    if status != STATUS_SUCCESS {
        return Err(format!(
            "NtSetSystemEnvironmentValueEx failed: 0x{:08X}",
            status.0 as u32
        ))
    }

    Ok(())
}

/// Check if test signing is enabled by querying SYSTEM_CODE_INTEGRITY_INFORMATION
pub fn is_test_signing_enabled() -> bool {
    let mut ci_info = SYSTEM_CODE_INTEGRITY_INFORMATION_STRUCT {
        length: mem::size_of::<SYSTEM_CODE_INTEGRITY_INFORMATION_STRUCT>() as u32,
        code_integrity_options: 0,
    };

    let mut return_length = 0u32;

    let status = unsafe {
        NtQuerySystemInformation(
            SYSTEM_CODE_INTEGRITY_INFORMATION,
            &mut ci_info as *mut _ as *mut std::ffi::c_void,
            ci_info.length,
            &mut return_length,
        )
    };

    if status == STATUS_SUCCESS {
        (ci_info.code_integrity_options & CODE_INTEGRITY_OPTION_TESTSIGNING) != 0
    } else {
        false
    }
}
