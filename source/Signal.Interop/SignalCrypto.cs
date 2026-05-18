using System.Runtime.InteropServices;

namespace Signal.Interop;

/// <summary>
/// This class must be marked 'partial' because the [LibraryImport] source generator 
/// will write the actual implementation behind the scenes.
/// </summary>
public static partial class SignalCrypto
{
    // Omit the .dll, .so, or .dylib extension so the runtime automatically resolves 
    // the correct file based on the operating system.
    private const string DllName = "signal_shim";

    // 1. The raw, private native method definition
    [LibraryImport(DllName)]
    private static partial int signal_shim_test_connection();

    // 2. The public, safe, managed wrapper your application will actually call
    public static int TestConnection()
    {
        // For a simple integer, there is no memory management required.
        // We just call the native method and return the result.
        return signal_shim_test_connection();
    }
}