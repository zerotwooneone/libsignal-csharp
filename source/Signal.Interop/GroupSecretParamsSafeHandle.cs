using System;
using System.Runtime.InteropServices;

namespace Signal.Interop;

public sealed partial class GroupSecretParamsSafeHandle : SafeHandle
{
    private GroupSecretParamsSafeHandle() : base(IntPtr.Zero, ownsHandle: true)
    {
    }

    internal GroupSecretParamsSafeHandle(nint handle) : base(IntPtr.Zero, ownsHandle: true)
    {
        SetHandle(handle);
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        SignalCrypto.Native.signal_zkgroup_group_secret_params_free(handle);
        return true;
    }
}
