using System;
using System.Runtime.InteropServices;

namespace Signal.Interop;

/// <summary>
/// SafeHandle wrapper for the native ProtocolAddress opaque handle.
/// Represents a sender's address (ACI + device ID) in the Signal protocol.
/// </summary>
public sealed partial class SenderAddressSafeHandle : SafeHandle
{
    private SenderAddressSafeHandle() : base(IntPtr.Zero, ownsHandle: true)
    {
    }

    internal SenderAddressSafeHandle(nint handle) : base(IntPtr.Zero, ownsHandle: true)
    {
        SetHandle(handle);
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        SignalCrypto.Native.signal_protocol_sender_address_free(handle);
        return true;
    }
}
