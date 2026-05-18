\# Signal Shim (Rust FFI)



This directory contains the Rust Foreign Function Interface (FFI) shim that bridges the official Signal cryptographic core (`libsignal-protocol`) to the Percolator .NET 9 application. 



It compiles the complex, constant-time Rust cryptography into a flat, C-compatible dynamic library (`signal\_shim.dll` / `libsignal\_shim.so`) that C# can safely consume via `\[LibraryImport]`.



\## ⚠️ Windows Setup Prerequisites



Building this project on Windows requires specific system-level dependencies. If you are setting this up on a fresh machine, you must install the following before running `cargo build`.



\### 1. The Rust Toolchain

Install the standard Rust compiler and package manager via \[rustup.rs](https://rustup.rs/).

\* Ensure you install the `x86\_64-pc-windows-msvc` toolchain (this is usually the default on Windows).



\### 2. C++ Build Tools \& Windows SDK (Fixes LNK1104)

The Rust compiler relies on the Microsoft C++ linker (`link.exe`) and the Windows C Runtime (`msvcrt.lib`). 

1\. Open the \*\*Visual Studio Installer\*\*.

2\. Modify your installation and check \*\*Desktop development with C++\*\*.

3\. In the installation details panel, ensure both of these are checked:

&#x20;  \* \*\*MSVC v143 - VS 2022 C++ x64/x86 build tools (Latest)\*\*

&#x20;  \* \*\*Windows 11 SDK\*\* (or Windows 10 SDK)



\### 3. Protocol Buffers Compiler (Fixes "Could not find protoc")

Signal uses protobufs extensively. The Rust build script needs the `protoc.exe` compiler to generate code.

1\. Go to the \[Protocol Buffers GitHub Releases](https://github.com/protocolbuffers/protobuf/releases).

2\. Download the latest `protoc-<version>-win64.zip`.

3\. Extract it to a permanent location (e.g., `C:\\protoc`).

4\. Add the `bin` folder (e.g., `C:\\protoc\\bin`) to your System `PATH` Environment Variable.



> \*\*Crucial:\*\* After installing these dependencies or updating your `PATH`, you must completely close and reopen your PowerShell terminal, otherwise the build will still fail.



\---



\## 🛠️ Building the Library



Once the prerequisites are installed, you can build the native library. Open PowerShell, navigate to this `signal\_shim` directory, and run:



```powershell

cargo build --release

```



\*\*What happens during the build:\*\*

1\. Cargo reaches out to GitHub and clones the `libsignal` repository specified in `Cargo.toml`.

2\. It compiles the Protocol Buffers.

3\. It compiles the Signal cryptography using the MSVC linker.

4\. It compiles our C-ABI wrapper functions defined in `src/lib.rs`.



\*\*Output Location:\*\*

The resulting compiled binary will be located at:

`target\\release\\signal\_shim.dll`



\---



\## 🔗 .NET Integration



You generally \*\*do not\*\* need to run `cargo build` manually while developing Percolator. 



The parent .NET solution (`Signal.Interop.csproj`) is configured with MSBuild targets that automatically trigger this Cargo build and copy the resulting native binary directly into the root `dist/` directory whenever you run `dotnet build` from the repository root.



\### Memory Management Note

Because memory allocated by Rust cannot be safely freed by the .NET Garbage Collector, every string or buffer allocated and returned by this shim must have a corresponding `free` function exported (e.g., `signal\_free\_string`). The C# wrapper must guarantee these are called via `try/finally` blocks to prevent memory leaks.

