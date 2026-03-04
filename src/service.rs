use std::path::Path;
use std::thread;
use std::time::Duration;

use windows::core::PCWSTR;
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, CreateServiceW, DeleteService, OpenSCManagerW,
    OpenServiceW, StartServiceW, SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS,
    SERVICE_CONTROL_STOP, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
    SERVICE_KERNEL_DRIVER, SERVICE_STATUS,
};

/// Stop and delete a service if it exists. Ignores errors silently.
pub fn stop_and_delete_service(service_name: &str) {
    let wide_name: Vec<u16> = service_name.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS);
        let scm = match scm {
            Ok(h) => h,
            Err(_) => return,
        };

        let service = OpenServiceW(scm, PCWSTR(wide_name.as_ptr()), SERVICE_ALL_ACCESS);
        let service = match service {
            Ok(h) => h,
            Err(_) => {
                let _ = CloseServiceHandle(scm);
                return;
            }
        };

        // Try to stop the service
        let mut status = SERVICE_STATUS::default();
        let _ = ControlService(service, SERVICE_CONTROL_STOP, &mut status);

        // Wait a moment for it to stop
        thread::sleep(Duration::from_millis(500));

        // Delete the service
        let _ = DeleteService(service);

        let _ = CloseServiceHandle(service);
        let _ = CloseServiceHandle(scm);
    }

    println!("[+] Service '{}' cleaned up.", service_name);
}

/// Create a kernel driver service and start it (loads the driver).
pub fn create_and_start_service(service_name: &str, driver_path: &Path) -> Result<(), String> {
    let wide_name: Vec<u16> = service_name.encode_utf16().chain(std::iter::once(0)).collect();

    // The driver path must use the \??\ prefix for kernel driver services
    let driver_str = driver_path.to_string_lossy();
    let binary_path = if driver_str.starts_with(r"\\?\") {
        // Convert \\?\ to \??\  for NT path
        format!(r"\??\{}", &driver_str[4..])
    } else {
        format!(r"\??\{}", driver_str)
    };
    let wide_path: Vec<u16> = binary_path.encode_utf16().chain(std::iter::once(0)).collect();

    unsafe {
        let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_ALL_ACCESS)
            .map_err(|e| format!("OpenSCManagerW failed: {}", e))?;

        let service = CreateServiceW(
            scm,
            PCWSTR(wide_name.as_ptr()),
            PCWSTR(wide_name.as_ptr()),
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            PCWSTR(wide_path.as_ptr()),
            PCWSTR::null(),
            None,
            PCWSTR::null(),
            PCWSTR::null(),
            PCWSTR::null(),
        )
        .map_err(|e| {
            let _ = CloseServiceHandle(scm);
            format!("CreateServiceW failed: {}", e)
        })?;

        // Start the service
        let result = StartServiceW(service, None);
        if let Err(e) = result {
            let err_msg = format!("StartServiceW failed: {}", e);
            let _ = DeleteService(service);
            let _ = CloseServiceHandle(service);
            let _ = CloseServiceHandle(scm);
            return Err(err_msg);
        }

        let _ = CloseServiceHandle(service);
        let _ = CloseServiceHandle(scm);
    }

    Ok(())
}
