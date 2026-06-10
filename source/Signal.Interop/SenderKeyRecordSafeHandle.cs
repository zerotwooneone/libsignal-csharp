using System;
using System.Runtime.InteropServices;

namespace Signal.Interop;

/// <summary>
/// SafeHandle wrapper for the native SenderKeyRecord opaque handle.
/// Represents the local ratchet state for group messaging.
/// </summary>
public sealed partial class SenderKeyRecordSafeHandle : SafeHandle
{
    private SenderKeyRecordSafeHandle() : base(IntPtr.Zero, ownsHandle: true)
    {
    }

    internal SenderKeyRecordSafeHandle(nint handle) : base(IntPtr.Zero, ownsHandle: true)
    {
        SetHandle(handle);
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        SignalCrypto.Native.signal_protocol_sender_key_record_free(handle);
        return true;
    }
}
