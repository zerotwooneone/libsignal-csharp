using System;
using System.Runtime.InteropServices;

namespace Signal.Interop;

public sealed partial class ServerSecretParamsSafeHandle : SafeHandle
{
    private ServerSecretParamsSafeHandle() : base(IntPtr.Zero, ownsHandle: true)
    {
    }

    internal ServerSecretParamsSafeHandle(nint handle) : base(IntPtr.Zero, ownsHandle: true)
    {
        SetHandle(handle);
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        SignalCrypto.Native.signal_zkgroup_server_secret_params_free(handle);
        return true;
    }
}
