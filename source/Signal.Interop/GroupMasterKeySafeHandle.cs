using System;
using System.Runtime.InteropServices;

namespace Signal.Interop;

public sealed partial class GroupMasterKeySafeHandle : SafeHandle
{
    private GroupMasterKeySafeHandle() : base(IntPtr.Zero, ownsHandle: true)
    {
    }

    internal GroupMasterKeySafeHandle(nint handle) : base(IntPtr.Zero, ownsHandle: true)
    {
        SetHandle(handle);
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        SignalCrypto.Native.signal_zkgroup_group_master_key_free(handle);
        return true;
    }
}
