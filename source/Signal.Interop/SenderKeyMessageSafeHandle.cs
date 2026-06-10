using System;
using System.Runtime.InteropServices;

namespace Signal.Interop;

/// <summary>
/// SafeHandle wrapper for the native SenderKeyMessage opaque handle.
/// Represents an encrypted group message with key ID header.
/// </summary>
public sealed partial class SenderKeyMessageSafeHandle : SafeHandle
{
    private SenderKeyMessageSafeHandle() : base(IntPtr.Zero, ownsHandle: true)
    {
    }

    internal SenderKeyMessageSafeHandle(nint handle) : base(IntPtr.Zero, ownsHandle: true)
    {
        SetHandle(handle);
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        SignalCrypto.Native.signal_protocol_sender_key_message_free(handle);
        return true;
    }
}
