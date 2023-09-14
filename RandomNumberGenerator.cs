namespace RandomNumberGenerator;

using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security;

public static class RandomNumberGenerator
{
    // VirtualProtectEx execute flags.
    private const byte EXECUTE_READWRITE = 0x40;

    [DllImport("kernel32.dll")]
    private static extern bool VirtualProtectEx
    (
        IntPtr hProcess,
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint flNewProtect,
        out uint lpflOldProtect
    );

    #region byte code
    private static readonly byte[] rdseedAxByteCode =
    {
        0x66, 0x31, 0xC0,      // xor ax, ax
        0x66, 0x0F, 0xC7, 0xF8,// rdseed ax
        0xC3                   // ret
    };

    private static readonly byte[] rdseedEaxByteCode =
    {
        0x31, 0xC0,      // xor eax, eax
        0x0F, 0xC7, 0xF8,// rdseed eax
        0xC3             // ret
    };

    private static readonly byte[] rdseedRaxByteCode =
    {
        0x48, 0x31, 0xC0,      // xor rax, rax
        0x48, 0x0F, 0xC7, 0xF8,// rdseed rax
        0xC3                   // ret
    };

    /*
        EBX: 00000000 00000000 01000000 00000000
                                ^(RDSEED supported)

        ECX: 00000000 00000000 00000000 00000100
                                             ^(RDRAND supported)

        To determine programmatically whether a given Intel platform supports the RDSEED instruction, 
        developers can use the CPUID instruction to examine bit 18 of the EBX register.

        To determine programmatically whether a given Intel platform supports RDRAND, 
        developers can use the CPUID instruction to examine bit 30 of the ECX register.
    */

    private static readonly byte[] rdSeedSupportedByteCode = new byte[]
    {
        0xB8, 0x07, 0x00, 0x00, 0x00,// mov 	eax, 7 
        0x31, 0xC9,                  // xor 	ecx, ecx
        0x31, 0xD2,                  // xor 	edx, edx
        0x31, 0xDB,                  // xor 	ebx, ebx
        0x0F, 0xA2,                  // cpuid
        0x0F, 0xBA, 0xE3, 0x12,      // bt 		ebx, 18
        0x31, 0xC0,                  // xor    	eax, eax
        0x0F, 0x94, 0xC0,            // sete   	al
        0xC3                         // ret
    };

    private static readonly byte[] rdRandSupportedByteCode = new byte[]
    {
        0xB8, 0x07, 0x00, 0x00, 0x00,// mov     eax, 7 
        0x31, 0xC9,                  // xor     ecx, ecx
        0x31, 0xD2,                  // xor     edx, edx
        0x31, 0xDB,                  // xor     ebx, ebx
        0x0F, 0xA2,                  // cpuid        
        0x0F, 0xBA, 0xE1, 0x1E,      // bt      ecx, 30
        0x31, 0xC0,                  // xor     eax, eax
        0x0F, 0x94, 0xC0,            // sete    al
        0xC3                         // ret
    };
    #endregion

    private enum Register
    {
        AX,
        EAX,
        RAX
    }

    private static readonly Dictionary<Register, byte[]> rdseedByteCodeLookup = new()
    {
        { Register.AX, rdseedAxByteCode },
        { Register.EAX, rdseedEaxByteCode },
        { Register.RAX, rdseedRaxByteCode }
    };

    [SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private unsafe delegate bool IsSupported();

    [SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private unsafe delegate void* RDSeed();

    private static RDSeed? GenerateShort = null;
    private static RDSeed? GenerateInt = null;
    private static RDSeed? GenerateLong = null;

    private static readonly bool Is64Bit = IntPtr.Size == 8;

    /// <summary>
    /// RdSeed is similar to RdRand and provides lower-level access to the entropy-generating hardware.
    /// This generator is compliant with security and cryptographic standards such as NIST SP 800-90A, FIPS 140-2, and ANSI X9.82.
    /// </summary>
    public static readonly bool SupportsRdSeed = false;

    /// <summary>
    /// This generator is compliant with security and cryptographic standards such as NIST SP 800-90A, FIPS 140-2, and ANSI X9.82.
    /// </summary>
    public static readonly bool SupportsRdRand = false;

    /// <summary>
    /// Does this CPU support the RdSeed or RdRand instruction?
    /// </summary>
    public static readonly bool SupportedByCPU = false;

    static RandomNumberGenerator()
    {
        SupportsRdSeed = Internal_IsRdSeedSupported();
        SupportsRdRand = Internal_IsRdRandSupported();
        SupportedByCPU = SupportsRdSeed || SupportsRdSeed;

        if (!SupportedByCPU)
            return;

        GenerateShort = Internal_GetRdSeedFunctionDelegate(Register.AX);
        GenerateInt = Internal_GetRdSeedFunctionDelegate(Register.EAX);

        if (Is64Bit)
            GenerateLong = Internal_GetRdSeedFunctionDelegate(Register.RAX);
    }

    private static unsafe bool Internal_IsRdSeedSupported()
        => Internal_GetFunctionDelegate<IsSupported>(rdSeedSupportedByteCode)();

    private static unsafe bool Internal_IsRdRandSupported()
        => Internal_GetFunctionDelegate<IsSupported>(rdRandSupportedByteCode)();

    private static unsafe RDSeed Internal_GetRdSeedFunctionDelegate(Register register) 
        => Internal_GetFunctionDelegate<RDSeed>(rdseedByteCodeLookup[register]);

    private static unsafe TReturnDelegate Internal_GetFunctionDelegate<TReturnDelegate>(byte[] assembly) 
        where TReturnDelegate : Delegate
    {
        fixed (byte* byteCode = assembly)
        {
            var byteCodeAddress = (IntPtr)byteCode;

            // Mark memory as EXECUTE_READWRITE to prevent DEP exceptions
            if (!VirtualProtectEx(Process.GetCurrentProcess().Handle, byteCodeAddress,
                (UIntPtr)assembly.Length, EXECUTE_READWRITE, out uint _))
                throw new Win32Exception();

            return Marshal.GetDelegateForFunctionPointer<TReturnDelegate>(byteCodeAddress);
        }
    }

    private static long Internal_ConvertToPositive(in long number)
    {
        if (number >= 0)
            return number;

        return ~number + 1;
    }

    /// <summary>
    /// Returns a random integer using rdseed.
    /// </summary>
    /// <param name="allowNegatives">If true, this function will return negative values.</param>
    /// <returns>A 64-bit signed integer that is greater than or equal to <see cref="long.MinValue"/> and less than <see cref="long.MaxValue"/>.</returns>
    /// <exception cref="NotSupportedException">Throws when the CPU being used does not support either RdSeed or RdRand.</exception>
    /// <exception cref="InvalidOperationException">Throws when the minimum value can exceeds or is equal to the maximum value.</exception>
    /// <exception cref="NullReferenceException">Throws when the 'GenerateLong' RDSeed delegate is null.</exception>
    public static unsafe long GenerateRandomLong(bool allowNegatives = true)
    {
        if (!SupportedByCPU)
            throw new NotSupportedException("RdSeed & RdRand are not supported by this CPU!");

        if (!Is64Bit)
            throw new InvalidOperationException("This application must be 64 bit to generate a random 64 bit value!");

        if (GenerateLong is null)
            throw new NullReferenceException("The 'GenerateLong' RDSeed delegate was null!");

        if (allowNegatives)
            return (long)GenerateLong();

        return Internal_ConvertToPositive((long)GenerateLong());
    }

    /// <summary>
    /// Returns a random integer using rdseed.
    /// </summary>
    /// <param name="minimumValue">Minimum value that can be generated.</param>
    /// <param name="maximumValue">Maximum value that can be generated.</param>
    /// <returns>A 64-bit signed integer that is greater than or equal to minimumValue and less than maximumValue.</returns>
    /// <exception cref="NotSupportedException">Throws when the CPU being used does not support either RdSeed or RdRand.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Throws when the minimum value can exceeds or is equal to the maximum value.</exception>
    /// <exception cref="InvalidOperationException">Throws when the application or system architecture is 32 bit.</exception>
    /// <exception cref="NullReferenceException">Throws when the 'GenerateLong' RDSeed delegate is null.</exception>
    public static unsafe long GenerateRandomLong(long minimumValue, long maximumValue)
    {
        if (minimumValue >= maximumValue)
            throw new ArgumentOutOfRangeException("Minimum value can not exceed or equal maximum value!");

        return (GenerateRandomLong(false) % maximumValue) + minimumValue;
    }

    /// <summary>
    /// Returns a random integer using rdseed.
    /// </summary>
    /// <param name="allowNegatives">If true, this function will return negative values.</param>
    /// <returns>A 32-bit signed integer that is greater than or equal to <see cref="int.MinValue"/> and less than <see cref="int.MaxValue"/>.</returns>
    /// <exception cref="NotSupportedException">Throws when the CPU being used does not support either RdSeed or RdRand.</exception>
    /// <exception cref="NullReferenceException">Throws when the 'GenerateInt' RDSeed delegate is null.</exception>
    public static unsafe int GenerateRandomInt(bool allowNegatives = true)
    {
        if (!SupportedByCPU)
            throw new NotSupportedException("RdSeed & RdRand are not supported by this CPU!");

        if (GenerateInt is null)
            throw new NullReferenceException("The 'GenerateInt' RDSeed delegate was null!");

        if (allowNegatives)
            return (int)GenerateInt();

        return (int)Internal_ConvertToPositive((int)GenerateInt());
    }

    /// <summary>
    /// Returns a random integer using rdseed.
    /// </summary>
    /// <param name="minimumValue">Minimum value that can be generated.</param>
    /// <param name="maximumValue">Maximum value that can be generated.</param>
    /// <returns>A 32-bit signed integer that is greater than or equal to minimumValue and less than maximumValue.</returns>
    /// <exception cref="NotSupportedException">Throws when the CPU being used does not support either RdSeed or RdRand.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Throws when the minimum value can exceeds or is equal to the maximum value.</exception>
    /// <exception cref="NullReferenceException">Throws when the 'GenerateInt' RDSeed delegate is null.</exception>
    public static unsafe int GenerateRandomInt(int minimumValue, int maximumValue)
    {
        if (minimumValue >= maximumValue)
            throw new ArgumentOutOfRangeException("Minimum value can not exceed or equal maximum value!");

        return (GenerateRandomInt(false) % maximumValue) + minimumValue;
    }

    /// <summary>
    /// Returns a random integer using rdseed.
    /// </summary>
    /// <param name="allowNegatives">If true, this function will return negative values.</param>
    /// <returns>A 32-bit signed integer that is greater than or equal to <see cref="short.MinValue"/> and less than <see cref="short.MaxValue"/>.</returns>
    /// <exception cref="NotSupportedException">Throws when the CPU being used does not support either RdSeed or RdRand.</exception>
    /// <exception cref="NullReferenceException">Throws when the 'GenerateShort' RDSeed delegate is null.</exception>
    public static unsafe short GenerateRandomShort(bool allowNegatives = true)
    {
        if (!SupportedByCPU)
            throw new NotSupportedException("RdSeed & RdRand are not supported by this CPU!");

        if (GenerateShort is null)
            throw new NullReferenceException("The 'GenerateShort' RDSeed delegate was null!");

        if (allowNegatives)
            return (short)GenerateShort();

        return (short)Internal_ConvertToPositive((short)GenerateShort());
    }

    /// <summary>
    /// Returns a random integer using rdseed.
    /// </summary>
    /// <param name="minimumValue">Minimum value that can be generated.</param>
    /// <param name="maximumValue">Maximum value that can be generated.</param>
    /// <returns>A 16-bit signed integer that is greater than or equal to minimumValue and less than maximumValue.</returns>
    /// <exception cref="NotSupportedException">Throws when the CPU being used does not support either RdSeed or RdRand.</exception>
    /// <exception cref="ArgumentOutOfRangeException">Throws when the minimum value can exceeds or is equal to the maximum value.</exception>
    /// <exception cref="NullReferenceException">Throws when the 'GenerateShort' RDSeed delegate is null.</exception>
    public static unsafe short GenerateRandomShort(short minimumValue, short maximumValue)
    {
        if (minimumValue >= maximumValue)
            throw new ArgumentOutOfRangeException("Minimum value can not exceed or equal maximum value!");

        return (short)((GenerateRandomShort(false) % maximumValue) + minimumValue);
    }
}
