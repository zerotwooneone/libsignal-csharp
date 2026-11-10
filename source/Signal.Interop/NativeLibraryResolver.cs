using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Signal.Interop;

/// <summary>
/// Configures idiomatic cross-platform resolution of the native signal_shim library.
/// Supports standard .NET 'runtimes/{rid}/native/' directory layout as well as flat output directories.
/// </summary>
internal static class NativeLibraryResolver
{
    private const string TargetLibraryName = "signal_shim";

#pragma warning disable CA2255 // ModuleInitializer is explicitly used for native library resolution in this library
    [ModuleInitializer]
    internal static void Initialize()
    {
        NativeLibrary.SetDllImportResolver(typeof(SignalCrypto).Assembly, ResolveNativeLibrary);
    }
#pragma warning restore CA2255

    private static IntPtr ResolveNativeLibrary(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != TargetLibraryName)
        {
            return IntPtr.Zero;
        }

        string nativeFileName = GetNativeLibraryFileName();
        string rid = GetCurrentRuntimeIdentifier();
        string baseDir = AppContext.BaseDirectory;
        string? assemblyDir = Path.GetDirectoryName(assembly.Location);

        // Candidate paths in preferred probing order:
        // 1. AppContext.BaseDirectory/runtimes/{rid}/native/{nativeFileName}
        // 2. assemblyDir/runtimes/{rid}/native/{nativeFileName}
        // 3. Fallback to generic OS-arch if different from specific RID
        // 4. AppContext.BaseDirectory/{nativeFileName} (flat layout / backwards compat)
        // 5. assemblyDir/{nativeFileName}
        var candidates = new List<string?>
        {
            Path.Combine(baseDir, "runtimes", rid, "native", nativeFileName),
            !string.IsNullOrEmpty(assemblyDir) ? Path.Combine(assemblyDir, "runtimes", rid, "native", nativeFileName) : null
        };

        // Also check RuntimeInformation.RuntimeIdentifier if it differs (e.g. distro-specific RIDs)
        string runtimeId = RuntimeInformation.RuntimeIdentifier;
        if (!string.Equals(runtimeId, rid, StringComparison.OrdinalIgnoreCase))
        {
            candidates.Add(Path.Combine(baseDir, "runtimes", runtimeId, "native", nativeFileName));
            if (!string.IsNullOrEmpty(assemblyDir))
            {
                candidates.Add(Path.Combine(assemblyDir, "runtimes", runtimeId, "native", nativeFileName));
            }
        }

        // Flat layout fallbacks
        candidates.Add(Path.Combine(baseDir, nativeFileName));
        if (!string.IsNullOrEmpty(assemblyDir))
        {
            candidates.Add(Path.Combine(assemblyDir, nativeFileName));
        }

        foreach (string? candidate in candidates)
        {
            if (!string.IsNullOrEmpty(candidate) && File.Exists(candidate))
            {
                if (NativeLibrary.TryLoad(candidate, out IntPtr handle))
                {
                    return handle;
                }
            }
        }

        // Return IntPtr.Zero so the runtime falls back to standard probing mechanisms
        return IntPtr.Zero;
    }

    private static string GetCurrentRuntimeIdentifier()
    {
        string os = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "win" :
                    RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "linux" :
                    RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "osx" : "unknown";

        string arch = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => "x64",
            Architecture.Arm64 => "arm64",
            Architecture.X86 => "x86",
            Architecture.Arm => "arm",
            _ => "x64"
        };

        return $"{os}-{arch}";
    }

    private static string GetNativeLibraryFileName()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return "signal_shim.dll";
        }
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return "libsignal_shim.dylib";
        }
        return "libsignal_shim.so";
    }
}
