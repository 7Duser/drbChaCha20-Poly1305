using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;

namespace ChaCha20_Poly1305
{
    public static class bChaCha20Poly1305
    {
        private const int KeySize = 32;
        private const int NonceSize = 12;
        private const int TagSize = 16;

        public static (byte[] ciphertext, byte[] tag) Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default)
        {
            if (key.Length != KeySize) throw new ArgumentException($"Key must be {KeySize} bytes", nameof(key));
            if (nonce.Length != NonceSize) throw new ArgumentException($"Nonce must be {NonceSize} bytes", nameof(nonce));

            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[TagSize];
            Process(key, nonce, plaintext, ciphertext, tag, associatedData, encrypting: true);
            return (ciphertext, tag);
        }

        public static (byte[] plaintext, bool success) Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, ReadOnlySpan<byte> associatedData = default)
        {
            if (key.Length != KeySize) throw new ArgumentException($"Key must be {KeySize} bytes", nameof(key));
            if (nonce.Length != NonceSize) throw new ArgumentException($"Nonce must be {NonceSize} bytes", nameof(nonce));
            if (tag.Length != TagSize) throw new ArgumentException($"Tag must be {TagSize} bytes", nameof(tag));

            byte[] plaintext = new byte[ciphertext.Length];
            byte[] computedTag = new byte[TagSize];
            Process(key, nonce, ciphertext, plaintext, computedTag, associatedData, encrypting: false);

            if (CryptographicOperations.FixedTimeEquals(computedTag, tag)) return (plaintext, true);
            Array.Clear(plaintext, 0, plaintext.Length);
            return (null, false)!;
        }

        private static unsafe void Process(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> input, Span<byte> output, Span<byte> tag, ReadOnlySpan<byte> associatedData, bool encrypting)
        {
            byte* polyKeyBlock = stackalloc byte[64];
            ChaCha20.ProcessBlock(key, nonce, 0, polyKeyBlock);
            Span<byte> polyKey = new Span<byte>(polyKeyBlock, 32);
            
            ChaCha20.Process(key, nonce, 1, input, output);
            
            ReadOnlySpan<byte> ciphertextForTag = encrypting ? output : input;
            Poly1305.ComputeTag(polyKey, associatedData, ciphertextForTag, tag);
        }

        private static unsafe class ChaCha20
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static void Process(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter, ReadOnlySpan<byte> input, Span<byte> output)
            {
                int length = input.Length;
                if (length == 0) return;
                
                fixed (byte* inputPtr = input, outputPtr = output)
                {
                    byte* currentIn = inputPtr;
                    byte* currentOut = outputPtr;
                    int remaining = length;
                    uint currentCounter = counter;
                    
                    if (Avx2.IsSupported && remaining >= 256)
                    {
                        int blocks = remaining / 256;
                        remaining %= 256;
                        Process4BlocksAvx2(key, nonce, ref currentCounter, ref currentIn, ref currentOut, blocks);
                    }
                    
                    if (remaining > 0)
                    {
                        ProcessRemainingBlocks(key, nonce, currentCounter, currentIn, currentOut, remaining);
                    }
                }
            }

            private static void Process4BlocksAvx2(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ref uint counter, ref byte* input, ref byte* output, int blocks)
            {
                for (int i = 0; i < blocks; i++)
                {
                    byte* block = stackalloc byte[256];
                    Process4Blocks(key, nonce, counter, block);
                    
                    for (int j = 0; j < 8; j++)
                    {
                        Vector256<byte> vInput = Avx.LoadVector256(input + j * 32);
                        Vector256<byte> vBlock = Avx.LoadVector256(block + j * 32);
                        Vector256<byte> vOutput = Avx2.Xor(vInput, vBlock);
                        Avx.Store(output + j * 32, vOutput);
                    }
                    
                    input += 256;
                    output += 256;
                    counter += 4;
                }
            }

            private static void Process4Blocks(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter, byte* output)
            {
                for (uint i = 0; i < 4; i++)
                {
                    ProcessBlock(key, nonce, counter + i, output + i * 64);
                }
            }

            private static void ProcessRemainingBlocks(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter, byte* input, byte* output, int length)
            {
                byte* block = stackalloc byte[64];
                while (length > 0)
                {
                    ProcessBlock(key, nonce, counter, block);
                    int toProcess = Math.Min(length, 64);
                    
                    if (Avx2.IsSupported && toProcess >= 32)
                    {
                        Vector256<byte> vInput = Avx.LoadVector256(input);
                        Vector256<byte> vBlock = Avx.LoadVector256(block);
                        Vector256<byte> vOutput = Avx2.Xor(vInput, vBlock);
                        Avx.Store(output, vOutput);
                        
                        input += 32;
                        output += 32;
                        block += 32;
                        length -= 32;
                        toProcess -= 32;
                    }
                    
                    while (toProcess >= 8)
                    {
                        *(ulong*)output = *(ulong*)input ^ *(ulong*)block;
                        input += 8;
                        output += 8;
                        block += 8;
                        toProcess -= 8;
                        length -= 8;
                    }
                    
                    while (toProcess > 0)
                    {
                        *output = (byte)(*input ^ *block);
                        input++;
                        output++;
                        block++;
                        toProcess--;
                        length--;
                    }
                    
                    counter++;
                }
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static void ProcessBlock(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter, byte* output)
            {
                uint x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
                
                fixed (byte* keyPtr = key, noncePtr = nonce)
                {
                    x0 = 0x61707865;
                    x1 = 0x3320646e;
                    x2 = 0x79622d32;
                    x3 = 0x6b206574;
                    
                    x4 = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(keyPtr, 4));
                    x5 = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(keyPtr + 4, 4));
                    x6 = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(keyPtr + 8, 4));
                    x7 = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(keyPtr + 12, 4));
                    x8 = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(keyPtr + 16, 4));
                    x9 = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(keyPtr + 20, 4));
                    x10 = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(keyPtr + 24, 4));
                    x11 = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(keyPtr + 28, 4));
                    
                    x12 = counter;
                    
                    x13 = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(noncePtr, 4));
                    x14 = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(noncePtr + 4, 4));
                    x15 = BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(noncePtr + 8, 4));
                }

                uint i0 = x0, i1 = x1, i2 = x2, i3 = x3, 
                     i4 = x4, i5 = x5, i6 = x6, i7 = x7, 
                     i8 = x8, i9 = x9, i10 = x10, i11 = x11, 
                     i12 = x12, i13 = x13, i14 = x14, i15 = x15;

                for (int i = 0; i < 10; i++)
                {
                    QuarterRound(ref x0, ref x4, ref x8, ref x12);
                    QuarterRound(ref x1, ref x5, ref x9, ref x13);
                    QuarterRound(ref x2, ref x6, ref x10, ref x14);
                    QuarterRound(ref x3, ref x7, ref x11, ref x15);
                    
                    QuarterRound(ref x0, ref x5, ref x10, ref x15);
                    QuarterRound(ref x1, ref x6, ref x11, ref x12);
                    QuarterRound(ref x2, ref x7, ref x8, ref x13);
                    QuarterRound(ref x3, ref x4, ref x9, ref x14);
                }

                WriteUInt32LittleEndian(output, x0 + i0);
                WriteUInt32LittleEndian(output + 4, x1 + i1);
                WriteUInt32LittleEndian(output + 8, x2 + i2);
                WriteUInt32LittleEndian(output + 12, x3 + i3);
                WriteUInt32LittleEndian(output + 16, x4 + i4);
                WriteUInt32LittleEndian(output + 20, x5 + i5);
                WriteUInt32LittleEndian(output + 24, x6 + i6);
                WriteUInt32LittleEndian(output + 28, x7 + i7);
                WriteUInt32LittleEndian(output + 32, x8 + i8);
                WriteUInt32LittleEndian(output + 36, x9 + i9);
                WriteUInt32LittleEndian(output + 40, x10 + i10);
                WriteUInt32LittleEndian(output + 44, x11 + i11);
                WriteUInt32LittleEndian(output + 48, x12 + i12);
                WriteUInt32LittleEndian(output + 52, x13 + i13);
                WriteUInt32LittleEndian(output + 56, x14 + i14);
                WriteUInt32LittleEndian(output + 60, x15 + i15);
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static void WriteUInt32LittleEndian(byte* destination, uint value)
            {
                *destination = (byte)value;
                *(destination + 1) = (byte)(value >> 8);
                *(destination + 2) = (byte)(value >> 16);
                *(destination + 3) = (byte)(value >> 24);
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static uint RotateLeft(uint value, int offset) => 
                (value << offset) | (value >> (32 - offset));

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
            {
                a += b; d = RotateLeft(d ^ a, 16);
                c += d; b = RotateLeft(b ^ c, 12);
                a += b; d = RotateLeft(d ^ a, 8);
                c += d; b = RotateLeft(b ^ c, 7);
            }
        }

        private static unsafe class Poly1305
        {

            public static void ComputeTag(ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ciphertext, Span<byte> tag)
            {
                if (tag.Length != TagSize)
                    throw new ArgumentException($"Tag must be {TagSize} bytes", nameof(tag));

                uint r0 = BinaryPrimitives.ReadUInt32LittleEndian(key[..4]) & 0x0FFFFFFF;
                uint r1 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(4, 4)) & 0x0FFFFFFC;
                uint r2 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(8, 4)) & 0x0FFFFFFC;
                uint r3 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(12, 4)) & 0x0FFFFFFC;

                uint s1 = r1 * 5;
                uint s2 = r2 * 5;
                uint s3 = r3 * 5;

                ulong h0 = 0;
                ulong h1 = 0;
                ulong h2 = 0;
                ulong h3 = 0;

                ProcessData(aad, ref h0, ref h1, ref h2, ref h3, r0, r1, r2, r3, s1, s2, s3);
                
                ProcessData(ciphertext, ref h0, ref h1, ref h2, ref h3, r0, r1, r2, r3, s1, s2, s3);
                
                ProcessLength(aad.Length, ciphertext.Length, ref h0, ref h1, ref h2, ref h3, r0, r1, r2, r3, s1, s2, s3);

                ulong carry = h3 >> 32; 
                h3 &= 0xFFFFFFFF;
                h0 += carry * 5;
                carry = h0 >> 32; h0 &= 0xFFFFFFFF;
                h1 += carry;
                carry = h1 >> 32; h1 &= 0xFFFFFFFF;
                h2 += carry;
                carry = h2 >> 32; h2 &= 0xFFFFFFFF;
                h3 += carry;
                carry = h3 >> 32; h3 &= 0xFFFFFFFF;
                h0 += carry * 5;
                carry = h0 >> 32; h0 &= 0xFFFFFFFF;
                h1 += carry;

                h0 += BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(16, 4));
                h1 += BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(20, 4)) + (h0 >> 32);
                h0 &= 0xFFFFFFFF;
                h2 += BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(24, 4)) + (h1 >> 32);
                h1 &= 0xFFFFFFFF;
                h3 += BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(28, 4)) + (h2 >> 32);
                h2 &= 0xFFFFFFFF;

                BinaryPrimitives.WriteUInt32LittleEndian(tag, (uint)h0);
                BinaryPrimitives.WriteUInt32LittleEndian(tag.Slice(4), (uint)h1);
                BinaryPrimitives.WriteUInt32LittleEndian(tag.Slice(8), (uint)h2);
                BinaryPrimitives.WriteUInt32LittleEndian(tag.Slice(12), (uint)h3);
            }

            private static void ProcessData(ReadOnlySpan<byte> data, ref ulong h0, ref ulong h1, ref ulong h2, ref ulong h3, uint r0, uint r1, uint r2, uint r3, uint s1, uint s2, uint s3)
            {
                int remaining = data.Length;
                int offset = 0;

                while (remaining >= 16)
                {
                    ulong m0 = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, 4));
                    ulong m1 = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset + 4, 4));
                    ulong m2 = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset + 8, 4));
                    ulong m3 = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset + 12, 4));
                    offset += 16;
                    remaining -= 16;

                    h0 += m0;
                    h1 += m1;
                    h2 += m2;
                    h3 += m3;

                    ulong d0 = h0 * r0 + h1 * s3 + h2 * s2 + h3 * s1;
                    ulong d1 = h0 * r1 + h1 * r0 + h2 * s3 + h3 * s2;
                    ulong d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s3;
                    ulong d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0;

                    h0 = d0 & 0xFFFFFFFF;
                    ulong carry = d0 >> 32;
                    d1 += carry;
                    h1 = d1 & 0xFFFFFFFF;
                    carry = d1 >> 32;
                    d2 += carry;
                    h2 = d2 & 0xFFFFFFFF;
                    carry = d2 >> 32;
                    d3 += carry;
                    h3 = d3 & 0xFFFFFFFF;
                    carry = d3 >> 32;
                    h0 += carry * 5;
                }

                if (remaining > 0)
                {
                    Span<byte> block = stackalloc byte[16];
                    data.Slice(offset, remaining).CopyTo(block);
                    block[remaining] = 1;

                    ulong m0 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(0, 4));
                    ulong m1 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(4, 4));
                    ulong m2 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(8, 4));
                    ulong m3 = BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(12, 4));

                    h0 += m0;
                    h1 += m1;
                    h2 += m2;
                    h3 += m3;

                    ulong d0 = h0 * r0 + h1 * s3 + h2 * s2 + h3 * s1;
                    ulong d1 = h0 * r1 + h1 * r0 + h2 * s3 + h3 * s2;
                    ulong d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s3;
                    ulong d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0;

                    h0 = d0 & 0xFFFFFFFF;
                    ulong carry = d0 >> 32;
                    d1 += carry;
                    h1 = d1 & 0xFFFFFFFF;
                    carry = d1 >> 32;
                    d2 += carry;
                    h2 = d2 & 0xFFFFFFFF;
                    carry = d2 >> 32;
                    d3 += carry;
                    h3 = d3 & 0xFFFFFFFF;
                    carry = d3 >> 32;
                    h0 += carry * 5;
                }
            }

            private static void ProcessLength(int lenAad, int lenCipher, ref ulong h0, ref ulong h1, ref ulong h2, ref ulong h3, uint r0, uint r1, uint r2, uint r3, uint s1, uint s2, uint s3)
            {
                ulong lenAadLow = (uint)lenAad;
                ulong lenAadHigh = (ulong)lenAad >> 32;
                ulong lenCipherLow = (uint)lenCipher;
                ulong lenCipherHigh = (ulong)lenCipher >> 32;

                h0 += lenAadLow;
                h1 += lenAadHigh;
                h2 += lenCipherLow;
                h3 += lenCipherHigh;

                ulong d0 = h0 * r0 + h1 * s3 + h2 * s2 + h3 * s1;
                ulong d1 = h0 * r1 + h1 * r0 + h2 * s3 + h3 * s2;
                ulong d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s3;
                ulong d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0;

                h0 = d0 & 0xFFFFFFFF;
                ulong carry = d0 >> 32;
                d1 += carry;
                h1 = d1 & 0xFFFFFFFF;
                carry = d1 >> 32;
                d2 += carry;
                h2 = d2 & 0xFFFFFFFF;
                carry = d2 >> 32;
                d3 += carry;
                h3 = d3 & 0xFFFFFFFF;
                carry = d3 >> 32;
                h0 += carry * 5;
            }
        }
    }
}