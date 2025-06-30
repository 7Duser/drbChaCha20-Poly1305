using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ChaCha20_Poly1305
{
    public static class bChaCha20Poly1305
    {
        public const int KeySize = 32;
        public const int NonceSize = 12;
        private const int TagSize = 16;
        public static (byte[] ciphertext, byte[] tag) Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData = default)
        {
            if (key.Length != KeySize) throw new ArgumentException($"Key must be {KeySize} bytes", nameof(key));
            if (nonce.Length != NonceSize)
                throw new ArgumentException($"Nonce must be {NonceSize} bytes", nameof(nonce));

            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[TagSize];

            Process(key, nonce, plaintext, ciphertext, tag, associatedData, encrypting: true);

            return (ciphertext, tag);
        }

        public static (byte[] plaintext, bool success) Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, ReadOnlySpan<byte> associatedData = default)
        {
            if (key.Length != KeySize) throw new ArgumentException($"Key must be {KeySize} bytes", nameof(key));
            if (nonce.Length != NonceSize)
                throw new ArgumentException($"Nonce must be {NonceSize} bytes", nameof(nonce));
            if (tag.Length != TagSize) throw new ArgumentException($"Tag must be {TagSize} bytes", nameof(tag));

            var plaintext = new byte[ciphertext.Length];
            var computedTag = new byte[TagSize];

            Process(key, nonce, ciphertext, plaintext, computedTag, associatedData, encrypting: false);

            if (CryptographicOperations.FixedTimeEquals(computedTag, tag)) return (plaintext, true);
            Array.Clear(plaintext, 0, plaintext.Length);
            return (null, false)!;

        }

        private static void Process(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> input, Span<byte> output, Span<byte> tag, ReadOnlySpan<byte> associatedData, bool encrypting)
        {
            Span<byte> polyKey = stackalloc byte[32];
            ChaCha20.ProcessBlock(key, nonce, 0, polyKey);
            
            ChaCha20.Process(key, nonce, 1, input, output);
            
            var ciphertextForTag = encrypting ? output : input;
            Poly1305.ComputeTag(polyKey, associatedData, ciphertextForTag, tag);
        }

        private static class ChaCha20
        {
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            public static void Process(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter, ReadOnlySpan<byte> input, Span<byte> output)
            {
                Span<byte> block = stackalloc byte[64];
                int offset = 0;
                while (offset < input.Length)
                {
                    ProcessBlock(key, nonce, counter, block);
                    int bytesToProcess = Math.Min(input.Length - offset, 64);
                    for (int i = 0; i < bytesToProcess; i++)
                    {
                        output[offset + i] = (byte)(input[offset + i] ^ block[i]);
                    }

                    offset += 64;
                    counter++;
                }
            }

            public static void ProcessBlock(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter, Span<byte> output)
            {
                Span<uint> state = stackalloc uint[16];
                InitializeState(state, key, nonce, counter);

                Span<uint> workingState = stackalloc uint[16];
                state.CopyTo(workingState);

                for (int i = 0; i < 10; i++)
                {
                    QuarterRound(ref workingState[0], ref workingState[4], ref workingState[8], ref workingState[12]);
                    QuarterRound(ref workingState[1], ref workingState[5], ref workingState[9], ref workingState[13]);
                    QuarterRound(ref workingState[2], ref workingState[6], ref workingState[10], ref workingState[14]);
                    QuarterRound(ref workingState[3], ref workingState[7], ref workingState[11], ref workingState[15]);
                    QuarterRound(ref workingState[0], ref workingState[5], ref workingState[10], ref workingState[15]);
                    QuarterRound(ref workingState[1], ref workingState[6], ref workingState[11], ref workingState[12]);
                    QuarterRound(ref workingState[2], ref workingState[7], ref workingState[8], ref workingState[13]);
                    QuarterRound(ref workingState[3], ref workingState[4], ref workingState[9], ref workingState[14]);
                }

                for (int i = 0; i < 16; i++)
                {
                    state[i] += workingState[i];
                }

                MemoryMarshal.Write(output, state[0]);
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static void InitializeState(Span<uint> state, ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter)
            {
                state[0] = 0x61707865;
                state[1] = 0x3320646e;
                state[2] = 0x79622d32;
                state[3] = 0x6b206574;
                MemoryMarshal.Cast<byte, uint>(key).CopyTo(state.Slice(4, 8));
                state[12] = counter;
                MemoryMarshal.Cast<byte, uint>(nonce).CopyTo(state.Slice(13, 3));
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static uint RotateLeft(uint value, int offset) => (value << offset) | (value >> (32 - offset));

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static void QuarterRound(ref uint a, ref uint b, ref uint c, ref uint d)
            {
                a += b;
                d = RotateLeft(d ^ a, 16);
                c += d;
                b = RotateLeft(b ^ c, 12);
                a += b;
                d = RotateLeft(d ^ a, 8);
                c += d;
                b = RotateLeft(b ^ c, 7);
            }
        }

        private static class Poly1305
        {
            public static void ComputeTag(ReadOnlySpan<byte> key, ReadOnlySpan<byte> aad, ReadOnlySpan<byte> ciphertext, Span<byte> tag)
            {
                const int blockSize = 16;
                Span<byte> block = stackalloc byte[blockSize];

                uint r0 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(0, 4));
                uint r1 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(4, 4));
                uint r2 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(8, 4));
                uint r3 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(12, 4));

                r0 &= 0x03FFFFFF;
                r1 &= 0x03FFFF03;
                r2 &= 0x03FFC0FF;
                r3 &= 0x03F03FFF;

                uint s1 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(16, 4));
                uint s2 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(20, 4));
                uint s3 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(24, 4));
                uint s4 = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(28, 4));

                ulong h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;

                ProcessBlocks(aad, ref h0, ref h1, ref h2, ref h3, r0, r1, r2, r3, block);

                ProcessBlocks(ciphertext, ref h0, ref h1, ref h2, ref h3, r0, r1, r2, r3, block);

                block.Clear();
                BinaryPrimitives.WriteUInt64LittleEndian(block, (ulong)aad.Length);
                BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(8), (ulong)ciphertext.Length);
                ProcessFinalBlock(ref h0, ref h1, ref h2, ref h3, r0, r1, r2, r3, block);

                h2 += (ulong)((long)h1 >> 32);
                h1 &= 0xFFFFFFFF;
                h3 += (ulong)((long)h2 >> 32);
                h2 &= 0xFFFFFFFF;
                h4 += (ulong)((long)h3 >> 32);
                h3 &= 0xFFFFFFFF;
                h0 += (ulong)((long)h4 >> 32) * 5;
                h4 &= 0xFFFFFFFF;
                h1 += (ulong)((long)h0 >> 32);
                h0 &= 0xFFFFFFFF;

                ulong f = h0 + 5;
                h0 = f & 0xFFFFFFFF;
                h1 += (f >> 32);

                ulong f0 = h0 + s1;
                ulong f1 = h1 + s2 + (f0 >> 32);
                ulong f2 = h2 + s3 + (f1 >> 32);
                ulong f3 = h4 * 5 + h3 + s4 + (f2 >> 32);

                BinaryPrimitives.WriteUInt32LittleEndian(tag.Slice(0, 4), (uint)f0);
                BinaryPrimitives.WriteUInt32LittleEndian(tag.Slice(4, 4), (uint)f1);
                BinaryPrimitives.WriteUInt32LittleEndian(tag.Slice(8, 4), (uint)f2);
                BinaryPrimitives.WriteUInt32LittleEndian(tag.Slice(12, 4), (uint)f3);
            }

            private static void ProcessBlocks(ReadOnlySpan<byte> data, ref ulong h0, ref ulong h1, ref ulong h2, ref ulong h3, uint r0, uint r1, uint r2, uint r3, Span<byte> block)
            {
                int offset = 0;
                while (offset < data.Length)
                {
                    int chunkSize = Math.Min(data.Length - offset, 16);
                    data.Slice(offset, chunkSize).CopyTo(block);

                    if (chunkSize < 16)
                    {
                        block.Slice(chunkSize).Clear();
                        block[chunkSize] = 1;
                        ProcessFinalBlock(ref h0, ref h1, ref h2, ref h3, r0, r1, r2, r3, block);
                        break;
                    }

                    block[15] = (byte)(block[15] | 0x01);
                    ProcessFinalBlock(ref h0, ref h1, ref h2, ref h3, r0, r1, r2, r3, block);

                    offset += 16;
                }

                if (data.Length <= 0 || data.Length % 16 != 0) return;
                block.Clear();
                block[0] = 1;
                ProcessFinalBlock(ref h0, ref h1, ref h2, ref h3, r0, r1, r2, r3, block);
            }

            private static void ProcessFinalBlock(ref ulong h0, ref ulong h1, ref ulong h2, ref ulong h3, uint r0, uint r1, uint r2, uint r3, Span<byte> block)
            {
                h0 += BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(0, 4));
                h1 += BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(4, 4));
                h2 += BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(8, 4));
                h3 += BinaryPrimitives.ReadUInt32LittleEndian(block.Slice(12, 4)) | 0x01000000;

                ulong d0 = h0 * r0 + h1 * (5 * r3) + h2 * (5 * r2) + h3 * (5 * r1);
                ulong d1 = h0 * r1 + h1 * r0 + h2 * (5 * r3) + h3 * (5 * r2);
                ulong d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * (5 * r3);
                ulong d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0;

                d1 += d0 >> 32;
                d0 &= 0xFFFFFFFF;
                d2 += d1 >> 32;
                d1 &= 0xFFFFFFFF;
                d3 += d2 >> 32;
                d2 &= 0xFFFFFFFF;

                h0 = d0;
                h1 = d1;
                h2 = d2;
                h3 = d3;
            }
        }
    }
}