using System;
using System.Runtime.InteropServices;

namespace Signal.Interop;

public sealed partial class ServerPublicParamsSafeHandle : SafeHandle
{
    private ServerPublicParamsSafeHandle() : base(IntPtr.Zero, ownsHandle: true)
    {
    }

    internal ServerPublicParamsSafeHandle(nint handle) : base(IntPtr.Zero, ownsHandle: true)
    {
        SetHandle(handle);
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        SignalCrypto.Native.signal_zkgroup_server_public_params_free(handle);
        return true;
    }
}
