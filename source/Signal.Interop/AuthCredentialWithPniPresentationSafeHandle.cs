using System;
using System.Runtime.InteropServices;

namespace Signal.Interop;

public sealed partial class AuthCredentialWithPniPresentationSafeHandle : SafeHandle
{
    private AuthCredentialWithPniPresentationSafeHandle() : base(IntPtr.Zero, ownsHandle: true)
    {
    }

    internal AuthCredentialWithPniPresentationSafeHandle(nint handle) : base(IntPtr.Zero, ownsHandle: true)
    {
        SetHandle(handle);
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        SignalCrypto.Native.signal_zkgroup_auth_credential_with_pni_presentation_free(handle);
        return true;
    }
}
