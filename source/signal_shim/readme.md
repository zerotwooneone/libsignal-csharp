# Signal Shim (Rust FFI)

This directory contains the Rust Foreign Function Interface (FFI) shim that bridges the official Signal cryptographic core (`libsignal-protocol`) to the Percolator .NET 9 application. 

It compiles the complex, constant-time Rust cryptography into a flat, C-compatible dynamic library (`signal_shim.dll` / `libsignal_shim.so` / `libsignal_shim.dylib`) that C# can safely consume via `[LibraryImport]`.

---

## ⚠️ Windows Setup Prerequisites

Building this project on Windows requires specific system-level dependencies. If you are setting this up on a fresh machine, you must install the following before running `cargo build`.

### 1. The Rust Toolchain
Install the standard Rust compiler and package manager via [rustup.rs](https://rustup.rs/).
* Ensure you install the `x86_64-pc-windows-msvc` toolchain (this is usually the default on Windows).

### 2. C++ Build Tools & Windows SDK (Fixes LNK1104)
The Rust compiler relies on the Microsoft C++ linker (`link.exe`) and the Windows C Runtime (`msvcrt.lib`). 
1. Open the **Visual Studio Installer**.
2. Modify your installation and check **Desktop development with C++**.
3. In the installation details panel, ensure both of these are checked:
   * **MSVC v143 - VS 2022 C++ x64/x86 build tools (Latest)**
   * **Windows 11 SDK** (or Windows 10 SDK)

### 3. Protocol Buffers Compiler (Fixes "Could not find protoc")
Signal uses protobufs extensively. The Rust build script needs the `protoc.exe` compiler to generate code.
1. Go to the [Protocol Buffers GitHub Releases](https://github.com/protocolbuffers/protobuf/releases).
2. Download the latest `protoc-<version>-win64.zip`.
3. Extract it to a permanent location (e.g., `C:\protoc`).
4. Add the `bin` folder (e.g., `C:\protoc\bin`) to your System `PATH` Environment Variable.

> **Crucial:** After installing these dependencies or updating your `PATH`, you must completely close and reopen your PowerShell terminal, otherwise the build will still fail.

---

## 🐧 Linux / Docker Build Instructions

To build `libsignal_shim.so` for Linux x86-64 / ARM64:

### Prerequisites (Ubuntu/Debian)
```bash
sudo apt update && sudo apt install -y build-essential protobuf-compiler curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### Build
From `source/signal_shim`:
```bash
cargo build --release
```
The compiled binary will be at `target/release/libsignal_shim.so`.

Copy it into the .NET runtime directory:
```bash
cp target/release/libsignal_shim.so ../Signal.Interop/runtimes/linux-x64/native/
```

*(Or via Docker from the repository root:)*
```bash
docker run --rm -v "$PWD:/repo" -w /repo/source/signal_shim rust:latest /bin/bash -c "apt-get update && apt-get install -y protobuf-compiler && cargo build --release && cp target/release/libsignal_shim.so ../Signal.Interop/runtimes/linux-x64/native/"
```

---

## 🛠️ Building the Library on Windows

Once the prerequisites are installed, you can build the native library. Open PowerShell, navigate to this `signal_shim` directory, and run:

```powershell
cargo build --release
```

**Output Location:**
The resulting compiled binary will be located at:
`target\release\signal_shim.dll`

---

## 🔗 .NET Integration & Runtimes Layout

You generally **do not** need to run `cargo build` manually while developing on Windows. 

The parent .NET project (`Signal.Interop.csproj`) automatically triggers `cargo build --release` and deploys the binary to:
- `runtimes/{rid}/native/` (e.g. `runtimes/win-x64/native/signal_shim.dll`)
- Root output directory (for backwards compatibility)

At runtime, `Signal.Interop` uses an automatic `NativeLibraryResolver` to discover and load the native binary from `runtimes/{rid}/native/` on Windows, Linux, and macOS.

### Memory Management Note

Because memory allocated by Rust cannot be safely freed by the .NET Garbage Collector, every string or buffer allocated and returned by this shim must have a corresponding `free` function exported (e.g., `signal_zkgroup_group_master_key_free`). The C# wrapper uses `SafeHandle` subclasses to guarantee these are called to prevent memory leaks.
