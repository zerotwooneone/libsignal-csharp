using System;
using System.Runtime.InteropServices;

namespace Signal.Interop;

public sealed partial class GroupPublicParamsSafeHandle : SafeHandle
{
    private GroupPublicParamsSafeHandle() : base(IntPtr.Zero, ownsHandle: true)
    {
    }

    internal GroupPublicParamsSafeHandle(nint handle) : base(IntPtr.Zero, ownsHandle: true)
    {
        SetHandle(handle);
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        SignalCrypto.Native.signal_zkgroup_group_public_params_free(handle);
        return true;
    }
}
