using System;
using System.Runtime.InteropServices;

namespace Signal.Interop
{
    /// <summary>
    /// Delegate for loading a SenderKeyRecord from the C# store.
    /// Called by Rust via the VTable.
    /// </summary>
    /// <param name="senderAddress">Pointer to the ProtocolAddress (opaque)</param>
    /// <param name="distributionIdBytes">Pointer to the distribution ID UUID bytes (16 bytes)</param>
    /// <param name="distributionIdLen">Length of distribution ID bytes (must be 16)</param>
    /// <param name="outRecord">Output pointer for the serialized record bytes (allocated by C#)</param>
    /// <param name="outLen">Output pointer for the length of the serialized record</param>
    /// <returns>0 on success, 1 if not found, negative on error</returns>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public unsafe delegate int LoadSenderKeyDelegate(
        IntPtr senderAddress,
        byte* distributionIdBytes,
        UIntPtr distributionIdLen,
        out IntPtr outRecord,
        out UIntPtr outLen
    );

    /// <summary>
    /// Delegate for storing a SenderKeyRecord to the C# store.
    /// Called by Rust via the VTable.
    /// </summary>
    /// <param name="senderAddress">Pointer to the ProtocolAddress (opaque)</param>
    /// <param name="distributionIdBytes">Pointer to the distribution ID UUID bytes (16 bytes)</param>
    /// <param name="distributionIdLen">Length of distribution ID bytes (must be 16)</param>
    /// <param name="recordBytes">Pointer to the serialized record bytes</param>
    /// <param name="recordLen">Length of the serialized record</param>
    /// <returns>0 on success, negative on error</returns>
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public unsafe delegate int StoreSenderKeyDelegate(
        IntPtr senderAddress,
        byte* distributionIdBytes,
        UIntPtr distributionIdLen,
        byte* recordBytes,
        UIntPtr recordLen
    );

    /// <summary>
    /// C-ABI VTable structure for SenderKeyStore callbacks.
    /// This struct is passed to Rust to enable synchronous key storage operations.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SenderKeyStoreVTable
    {
        /// <summary>
        /// Function pointer to the LoadSenderKey delegate.
        /// Returns 0 on success, 1 on not found, negative on error.
        /// </summary>
        public IntPtr LoadSenderKey;

        /// <summary>
        /// Function pointer to the StoreSenderKey delegate.
        /// Returns 0 on success.
        /// </summary>
        public IntPtr StoreSenderKey;
    }
}
