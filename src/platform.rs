use std::arch::x86_64::__cpuid;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::Win32::Security::{DuplicateTokenEx, SecurityImpersonation, TOKEN_ALL_ACCESS, TokenPrimary};
use windows::Win32::System::Threading::{CREATE_NEW_CONSOLE, LOGON_WITH_PROFILE, OpenProcess, PROCESS_QUERY_INFORMATION};
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
use windows::core::{PCWSTR, PWSTR};

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE) -> Self {
        Self(handle)
    }

    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

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
    let game_path = Path::new(cmd);
    let game_abs = std::fs::canonicalize(game_path)
        .map_err(|e| format!("Invalid game path '{}': {}", game_path.display(), e))?;
    let game_dir = game_abs
        .parent()
        .ok_or_else(|| format!("Game path has no parent directory: {}", game_abs.display()))?;

    let game_path_utf16: Vec<u16> = game_abs
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut cmd_utf16: Vec<u16> = format!("\"{}\"", game_abs.display())
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let game_dir_utf16: Vec<u16> = game_dir
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let hwnd = GetShellWindow();
        if hwnd.0.is_null() { return Err("Could not find Shell Window".into()); }

        let mut pid: u32 = 0;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));

        let process_handle = OwnedHandle::new(
            OpenProcess(PROCESS_QUERY_INFORMATION, false, pid)
                .map_err(|e| format!("OpenProcess failed: {}", e))?
        );

        let mut shell_token = HANDLE::default();
        OpenProcessToken(process_handle.raw(), TOKEN_ALL_ACCESS, &mut shell_token)
            .map_err(|e| format!("OpenProcessToken failed: {}", e))?;
        let shell_token = OwnedHandle::new(shell_token);

        let mut primary_token = HANDLE::default();
        DuplicateTokenEx(
            shell_token.raw(),
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut primary_token,
        ).map_err(|e| format!("DuplicateTokenEx failed: {}", e))?;
        let primary_token = OwnedHandle::new(primary_token);

        let mut si = STARTUPINFOW::default();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi = PROCESS_INFORMATION::default();

        CreateProcessWithTokenW(
            primary_token.raw(),
            LOGON_WITH_PROFILE,
            PCWSTR(game_path_utf16.as_ptr()),
            Some(PWSTR(cmd_utf16.as_mut_ptr())),
            CREATE_NEW_CONSOLE,
            None,
            PCWSTR(game_dir_utf16.as_ptr()),
            &si,
            &mut pi,
        ).map_err(|e| format!("CreateProcessWithTokenW failed: {}", e))?;

        let process = OwnedHandle::new(pi.hProcess);
        let thread = OwnedHandle::new(pi.hThread);
        let pid = pi.dwProcessId;

        println!("[+] Game started (PID {}). Waiting for it to exit...", pid);
        WaitForSingleObject(process.raw(), u32::MAX);

        let _ = thread;

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
