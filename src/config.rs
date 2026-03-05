use std::fs;
use std::path::{Path, PathBuf};

use crate::platform::CpuVendor;

pub struct LauncherConfig {
    pub game: PathBuf,
    pub driver: PathBuf,
    pub service_name: String,
}

impl LauncherConfig {
    fn new(vendor: &CpuVendor) -> Self {
        let driver = match vendor {
            CpuVendor::Intel => PathBuf::from("driver_intel/hyperkd.sys"),
            CpuVendor::AMD => PathBuf::from("driver_amd/SimpleSvm.sys"),
        };

        Self {
            game: PathBuf::from("game.exe"),
            driver: driver,
            service_name: "denuvo".to_string(),
        }
    }
}

impl LauncherConfig {
    pub fn from_file<P: AsRef<Path>>(path: P, cpu_vendor: &CpuVendor) -> Result<Self, String> {
        let path = path.as_ref();
        let mut config = Self::new(cpu_vendor);

        if let Ok(ini) = ini::Ini::load_from_file(path) {
            if let Some(section) = ini.section(Some("launcher")) {
                if let Some(game) = section.get("game") {
                    config.game = PathBuf::from(game);
                    println!("[*] Game path overridden by config: {}", config.game.display());
                }
                match cpu_vendor {
                    CpuVendor::Intel => {
                        if let Some(intel) = section.get("driver_intel") {
                            config.driver = PathBuf::from(intel);
                        }
                    }
                    CpuVendor::AMD => {
                        if let Some(amd) = section.get("driver_amd") {
                            config.driver = PathBuf::from(amd);
                        }
                    }
                }
                if let Some(service) = section.get("service_name") {
                    config.service_name = service.to_string();
                }
            }
        }

        if !config.game.exists() {
            if let Some(found_game) = Self::find_game() {
                config.game = found_game;
            } else {
                return Err(format!(
                    "Game executable '{}' not found and no other .exe files found in current directory.",
                    config.game.display()
                ));
            }
        }

        if !config.driver.exists() {
            if let Some(found_driver) = Self::find_driver(config.driver.file_name().and_then(|s| s.to_str()).unwrap_or("")) {
                config.driver = found_driver;
            } else {
                return Err(format!(
                    "Driver file '{}' not found in current directory or subdirectories.",
                    config.driver.display()
                ));
            }
        }

        Ok(config)
    }

    fn find_game() -> Option<PathBuf> {
        let current_exe = std::env::current_exe().ok();
        let mut best_file = None;
        let mut max_size = 0;

        if let Ok(entries) = fs::read_dir(".") {
            for entry in entries.flatten() {
                let path = entry.path();
                
                if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("exe") {
                    if let Some(ref current) = current_exe {
                        if path.canonicalize().ok() == current.canonicalize().ok() {
                            continue;
                        }
                    }

                    if let Ok(metadata) = entry.metadata() {
                        let size = metadata.len();
                        if size > max_size {
                            max_size = size;
                            best_file = Some(path);
                        }
                    }
                }
            }
        }

        best_file
    }

    fn find_driver(name: &str) -> Option<PathBuf> {
        let current_exe = std::env::current_exe().ok()?;
        let current_dir = current_exe.parent()?;

        for entry in walkdir::WalkDir::new(current_dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() && path.file_name().and_then(|s| s.to_str()) == Some(name) {
                return Some(path.to_path_buf());
            }
        }

        None
    }
}
