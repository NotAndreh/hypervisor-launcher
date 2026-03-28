#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![allow(non_snake_case)]

mod config;
mod platform;
mod service;

use std::path::{Path, PathBuf};

use tempfile::TempDir;
use windows::{Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxA}, core::{PCSTR, s}};

use crate::{config::LauncherConfig, platform::CpuVendor};

const AMD_FILES: &[&str] = &["SimpleSvm.sys"];
const INTEL_FILES: &[&str] = &[
    "hyperevade.dll",
    "hyperhv.dll",
    "hyperkd.sys",
    "hyperlog.dll",
    "hyperlog.inf",
    "kdserial.dll",
];

fn main() {
    if !platform::is_elevated() {
        eprintln!("[!] This launcher must be run as Administrator.");
        platform::wait_and_exit(1);
    }

    let vendor = platform::get_cpu_vendor()
        .map_err(|e| {
            eprintln!("[!] Failed to detect CPU vendor: {}", e);
            platform::wait_and_exit(1);
        })
        .unwrap();

    if let Err(e) = run(&vendor) {
        unsafe {
            MessageBoxA(
                None, 
                PCSTR::from_raw(format!("An error occurred:\n\n{}\0", e).as_ptr()),
                s!("Hypervisor Launcher - Error"),
                MB_ICONERROR | MB_OK,
            );
        }
        eprintln!("[!] {}", e);
        platform::wait_and_exit(1);
    }

    println!("[*] Done.");
    platform::wait_and_exit(0);
}

fn run(vendor: &CpuVendor) -> Result<(), String> {
    let cfg = LauncherConfig::from_file(PathBuf::from("reflex.ini"), vendor)?;

    println!("[*] Config loaded:");
    println!("    CPU Vendor:   {}", vendor.to_string());
    println!("    Game:         {}", cfg.game.display());
    println!("    Driver:       {}", cfg.driver.display());
    println!("    Service:      {}", cfg.service_name);

    let files = match vendor {
        CpuVendor::Intel => INTEL_FILES,
        CpuVendor::AMD => AMD_FILES
    };
    let driver_abs = std::fs::canonicalize(&cfg.driver)
        .map_err(|_| format!("Driver file not found: {}", cfg.driver.display()))?;
    println!("[*] Using driver: {}", driver_abs.display());

    let (tempdir, staged_driver_path) = stage_driver_files(&cfg.driver, files)?;
    println!(
        "[*] Driver copied to temporary path: {}",
        staged_driver_path.display()
    );

    println!("[*] Acquiring privileges...");
    if let Err(e) = platform::acquire_privileges() {
        return Err(format!("Failed to acquire privileges: {}", e));
    }
    println!("[+] Privileges acquired.");

    println!("[*] Cleaning up any existing service '{}'...", cfg.service_name);
    service::stop_and_delete_service(&cfg.service_name);

    println!("[*] Creating and starting service '{}'...", cfg.service_name);
    let driver_loaded = match service::create_and_start_service(&cfg.service_name, &staged_driver_path) {
        Ok(()) => {
            println!("[+] Driver loaded successfully.");
            true
        }
        Err(e) => {
            eprintln!("[!] Failed to load driver: {}", e);
            false
        }
    };

    if !driver_loaded {
        return Err("The driver couldn't be loaded. Be sure to have DSE disabled via the Windows advanced boot options.".to_string());
    }

    start_game_and_wait(&cfg.game);

    println!("[*] Stopping and deleting service '{}'...", cfg.service_name);
    service::stop_and_delete_service(&cfg.service_name);
    println!("[+] Service cleaned up.");

    if let Err(e) = tempdir.close() {
        eprintln!("[!] Failed to delete temporary directory: {}", e);
    }

    Ok(())
}

fn stage_driver_files(driver_source: &Path, files: &[&str]) -> Result<(TempDir, PathBuf), String> {
    let tempdir = TempDir::new()
        .map_err(|e| format!("Failed to create temporary directory: {}", e))?;

    let source_dir = driver_source.parent().ok_or_else(|| {
        format!(
            "Failed to determine parent directory for {}",
            driver_source.display()
        )
    })?;

    for file in files {
        let src = source_dir.join(file);
        let dst = tempdir.path().join(file);
        if let Err(e) = std::fs::copy(&src, &dst) {
            eprintln!(
                "[!] Failed to copy driver file '{}' to temp directory: {}",
                src.display(),
                e
            );
        }
    }

    let driver_name = driver_source
        .file_name()
        .ok_or_else(|| format!("Driver file has no name: {}", driver_source.display()))?;
    let staged_driver_path = tempdir.path().join(driver_name);

    std::fs::copy(driver_source, &staged_driver_path).map_err(|e| {
        format!(
            "Failed to copy primary driver '{}' to temp directory: {}",
            driver_source.display(),
            e
        )
    })?;

    Ok((tempdir, staged_driver_path))
}

fn start_game_and_wait(game_path: &Path) {
    println!("[*] Starting game (non-elevated): {}", game_path.display());
    match platform::launch_as_user(game_path.to_str().unwrap()) {
        Ok(pid) => {
            println!("[*] Game (PID {}) exited.", pid);
        }
        Err(e) => {
            eprintln!("[!] Failed to start game with limited token: {}", e);
        }
    }
}
