use std::ffi::c_void;
use std::path::Path;

use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING,
};
use windows::Win32::System::Diagnostics::Debug::{IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_FILE_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER};
use windows::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_READ, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile, PAGE_READONLY, SEC_IMAGE, UnmapViewOfFile
};
use windows::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE};
use windows::core::PCWSTR;

pub struct MappedImage {
    pub base: *const u8,
    pub size: usize,
    file_handle: HANDLE,
    mapping_handle: HANDLE,
}

impl MappedImage {
    pub fn map(path: &Path) -> Result<Self, String> {
        let wide_path: Vec<u16> = path
            .to_string_lossy()
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let file_handle = CreateFileW(
                PCWSTR(wide_path.as_ptr()),
                FILE_GENERIC_READ.0,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                Some(HANDLE::default()),
            )
            .map_err(|e| format!("CreateFileW failed: {}", e))?;

            if file_handle == INVALID_HANDLE_VALUE {
                return Err("CreateFileW returned INVALID_HANDLE_VALUE".into());
            }

            let mapping_handle = CreateFileMappingW(
                file_handle,
                None,
                PAGE_READONLY | SEC_IMAGE,
                0,
                0,
                PCWSTR::null(),
            )
            .map_err(|e| {
                let _ = CloseHandle(file_handle);
                format!("CreateFileMappingW failed: {}", e)
            })?;

            let view = MapViewOfFile(mapping_handle, FILE_MAP_READ, 0, 0, 0);
            if view.Value.is_null() {
                let _ = CloseHandle(mapping_handle);
                let _ = CloseHandle(file_handle);
                return Err("MapViewOfFile returned null".into());
            }

            let base = view.Value as *const u8;
            let dos = &*(base as *const IMAGE_DOS_HEADER);
            if dos.e_magic != IMAGE_DOS_SIGNATURE {
                let _ = UnmapViewOfFile(view);
                let _ = CloseHandle(mapping_handle);
                let _ = CloseHandle(file_handle);
                return Err("Invalid DOS signature".into());
            }

            let nt = &*(base.add(dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64);
            if nt.Signature != IMAGE_NT_SIGNATURE {
                let _ = UnmapViewOfFile(view);
                let _ = CloseHandle(mapping_handle);
                let _ = CloseHandle(file_handle);
                return Err("Invalid NT signature".into());
            }

            let size = nt.OptionalHeader.SizeOfImage as usize;

            Ok(MappedImage {
                base,
                size,
                file_handle,
                mapping_handle,
            })
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.base, self.size) }
    }

    pub fn nt_headers(&self) -> &IMAGE_NT_HEADERS64 {
        unsafe {
            let dos = &*(self.base as *const IMAGE_DOS_HEADER);
            &*(self.base.add(dos.e_lfanew as usize) as *const IMAGE_NT_HEADERS64)
        }
    }

    pub fn sections(&self) -> &[IMAGE_SECTION_HEADER] {
        let nt = self.nt_headers();
        let first_section = unsafe {
            (nt as *const IMAGE_NT_HEADERS64 as *const u8)
                .add(std::mem::size_of::<u32>()) // signature
                .add(std::mem::size_of::<IMAGE_FILE_HEADER>())
                .add(nt.FileHeader.SizeOfOptionalHeader as usize)
                as *const IMAGE_SECTION_HEADER
        };
        unsafe {
            std::slice::from_raw_parts(first_section, nt.FileHeader.NumberOfSections as usize)
        }
    }

    pub fn address_in_section(&self, addr: *const u8, section_name: &str) -> bool {
        if (addr as usize) < (self.base as usize) {
            return false;
        }
        let rva = (addr as usize) - (self.base as usize);
        if rva >= self.size {
            return false;
        }

        for section in self.sections() {
            let sec_start = section.VirtualAddress as usize;
            let sec_end = sec_start + unsafe { section.Misc.VirtualSize } as usize;
            if rva >= sec_start && rva < sec_end {
                let name = section_name_str(&section.Name);
                if name.eq_ignore_ascii_case(section_name) {
                    return true;
                }
            }
        }
        false
    }

    pub fn get_export(&self, name: &str) -> Option<*const u8> {
        let nt = self.nt_headers();
        let export_dir_rva = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize].VirtualAddress;
        let export_dir_size = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT.0 as usize].Size;

        if export_dir_rva == 0 {
            return None;
        }

        let base = self.base as usize;

        unsafe {
            let export_dir =
                &*((base + export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY);

            let functions =
                (base + export_dir.AddressOfFunctions as usize) as *const u32;
            let name_ordinals =
                (base + export_dir.AddressOfNameOrdinals as usize) as *const u16;
            let names =
                (base + export_dir.AddressOfNames as usize) as *const u32;

            let num_names = export_dir.NumberOfNames as usize;

            let mut low: i64 = 0;
            let mut high: i64 = num_names as i64 - 1;

            while high >= low {
                let mid = ((low + high) / 2) as usize;
                let name_rva = *names.add(mid);
                let export_name_ptr = (base + name_rva as usize) as *const u8;

                let export_name = std::ffi::CStr::from_ptr(export_name_ptr as *const i8)
                    .to_str()
                    .unwrap_or("");

                match export_name.cmp(name) {
                    std::cmp::Ordering::Less => low = mid as i64 + 1,
                    std::cmp::Ordering::Greater => high = mid as i64 - 1,
                    std::cmp::Ordering::Equal => {
                        let ordinal = *name_ordinals.add(mid) as usize;
                        if ordinal >= export_dir.NumberOfFunctions as usize {
                            return None;
                        }
                        let func_rva = *functions.add(ordinal);

                        // Check for forwarded export
                        if func_rva >= export_dir_rva
                            && func_rva < export_dir_rva + export_dir_size
                        {
                            return None; // forwarded
                        }

                        return Some((base + func_rva as usize) as *const u8);
                    }
                }
            }
        }

        None
    }
}

impl Drop for MappedImage {
    fn drop(&mut self) {
        unsafe {
            let view = MEMORY_MAPPED_VIEW_ADDRESS {
                Value: self.base as *mut c_void,
            };
            let _ = UnmapViewOfFile(view);
            let _ = CloseHandle(self.mapping_handle);
            let _ = CloseHandle(self.file_handle);
        }
    }
}

fn section_name_str(name: &[u8; 8]) -> &str {
    let end = name.iter().position(|&b| b == 0).unwrap_or(8);
    std::str::from_utf8(&name[..end]).unwrap_or("")
}
