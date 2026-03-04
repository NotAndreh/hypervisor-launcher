use std::arch::x86_64::__cpuid;

use windows::Win32::Security::{DuplicateTokenEx, SecurityImpersonation, TOKEN_ALL_ACCESS, TokenPrimary};
use windows::Win32::System::Threading::{CREATE_NEW_CONSOLE, CREATE_PROCESS_LOGON_FLAGS, OpenProcess, PROCESS_QUERY_INFORMATION};
use windows::Win32::UI::WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId};
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    Security::{
        GetTokenInformation,
        TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    },
    System::Threading::{
        GetCurrentProcess, OpenProcessToken, PROCESS_INFORMATION, STARTUPINFOW,
        WaitForSingleObject, CreateProcessWithTokenW
    },
};

pub enum CpuVendor {
    Intel,
    AMD
}

impl ToString for CpuVendor {
    fn to_string(&self) -> String {
        match self {
            CpuVendor::Intel => "Intel".to_string(),
            CpuVendor::AMD => "AMD".to_string(),
        }
    }
}

/// Get the CPU vendor string using the CPUID instruction.
pub fn get_cpu_vendor() -> Result<CpuVendor, String> {
    let result = __cpuid(0);
    let vendor = [
        result.ebx.to_le_bytes(),
        result.edx.to_le_bytes(),
        result.ecx.to_le_bytes(),
    ]
    .concat();

    let str = String::from_utf8_lossy(&vendor).to_string();
    match str.as_str() {
        "GenuineIntel" => Ok(CpuVendor::Intel),
        "AuthenticAMD" => Ok(CpuVendor::AMD),
        _ => Err(format!("Unknown CPU vendor: {}", str)),
    }
}

/// Check if the current process is running with elevated privileges.
pub fn is_elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );

        let _ = CloseHandle(token);
        ok.is_ok() && elevation.TokenIsElevated != 0
    }
}

/// Launch a process as non-elevated user (fixes games like AFOP).
pub fn launch_as_user(cmd: &str) -> Result<u32, String> {
    unsafe {
        let hwnd = GetShellWindow();
        if hwnd.0.is_null() { return Err("Could not find Shell Window".into()); }

        let mut pid: u32 = 0;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));

        let process_handle = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid)
            .map_err(|e| format!("OpenProcess failed: {}", e))?;

        let mut shell_token = HANDLE::default();
        OpenProcessToken(process_handle, TOKEN_ALL_ACCESS, &mut shell_token)
            .map_err(|e| format!("OpenProcessToken failed: {}", e))?;

        let mut primary_token = HANDLE::default();
        DuplicateTokenEx(
            shell_token,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut primary_token,
        ).map_err(|e| format!("DuplicateTokenEx failed: {}", e))?;

        let si = STARTUPINFOW::default();
        let mut pi = PROCESS_INFORMATION::default();
        let mut cmd_utf16: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();

        CreateProcessWithTokenW(
            primary_token,
            CREATE_PROCESS_LOGON_FLAGS(0),
            None,
            Some(windows::core::PWSTR(cmd_utf16.as_mut_ptr())),
            CREATE_NEW_CONSOLE,
            None,
            None,
            &si,
            &mut pi,
        ).map_err(|e| format!("CreateProcessWithTokenW failed: {}", e))?;

        let _ = CloseHandle(primary_token);
        let pid = pi.dwProcessId;

        println!("[+] Game started (PID {}). Waiting for it to exit...", pid);
        WaitForSingleObject(pi.hProcess, u32::MAX);

        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(pi.hThread);

        Ok(pid)
    }
}

pub fn wait_and_exit(code: i32) -> ! {
    if cfg!(debug_assertions) {
        println!("\nPress Enter to exit...");
        let mut input = String::new();
        let _ = std::io::stdin().read_line(&mut input);
    }

    std::process::exit(code);
}
