# Hypervisor Launcher

A lightweight launcher that automates loading a hypervisor driver (Intel or AMD), launching a game under it, and cleaning up afterward. It handles DSE (Driver Signature Enforcement) bypass via [EfiGuard](https://github.com/Mattiwatti/EfiGuard), and loads the appropriate driver based on your CPU.

## Download

Grab the latest build from GitHub:

- **Stable releases**: [Releases](https://github.com/NotAndreh/hypervisor-launcher/releases)
- **Nightly builds**: [Actions](https://github.com/NotAndreh/hypervisor-launcher/actions) (artifacts from the latest workflow run)

For debug logging, use the debug build, which will print detailed information about each step to the console.

## Usage

**Hypervisor Launcher works out of the box without any configuration file.** Simply place the executable in the same directory as your game and driver files, and run it as Administrator.

By default, the launcher will:

1. Detect your CPU vendor (Intel or AMD) automatically.
2. Look for the driver in `driver_intel/hyperkd.sys` or `driver_amd/SimpleSvm.sys` depending on your CPU.
3. Find the game executable automatically, it picks the largest `.exe` in the current directory.
4. Register the driver as a service named `denuvo`, start it, launch the game, and clean up once the game exits.

## Configuration (Optional)

If you need to override the defaults, create a `reflex.ini` file in the same directory as the launcher:

```ini
[launcher]
game=game.exe
driver_intel=driver_intel/hyperkd.sys
driver_amd=driver_amd/SimpleSvm.sys
service_name=denuvo
```

This can be useful in case of Unity games, where the main exe isn't the largest one in the directory.

## Building from Source

```bash
# Debug build
cargo build

# Release build (optimized, stripped)
cargo build --release
```

The output binary will be in `target/debug/` or `target/release/`.

## Disclaimer

This project is for educational and research purposes only. Use responsibly and respect software licenses.
