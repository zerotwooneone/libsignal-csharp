// We include this to ensure the compiler actually downloads and links the Signal library,
// even if we aren't calling its specific cryptographic functions in this dummy test.
use libsignal_protocol::*; 

/// `#[no_mangle]` is critical. It turns off Rust's name mangling so the compiled 
/// function retains the exact name "signal_shim_test_connection" in the exported DLL.
/// `extern "C"` forces the function to use the standard C calling convention.
#[no_mangle]
pub extern "C" fn signal_shim_test_connection() -> i32 {
    // A simple identifiable number to prove the .NET Interop successfully called this library
    42 
}