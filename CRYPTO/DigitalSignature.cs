using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;
using static CRYPTO_MATH.Math;

namespace CRYPTO_SIGNATURE {
    static class DigitalSignature {
        enum State { Working, FullConstruct, AppendLen, Done }
        static uint K(uint t) {
            if (t < 20) return 0x5a827999;
            if (t < 40) return 0x6ed9eba1;
            if (t < 60) return 0x8f1bbcdc;
            if (t < 80) return 0xca62c1d6;
            return 0;
        }
        static uint Ft(uint t, uint m, uint l, uint k) {
            if (t < 20) return m & l | ~m & k;
            if (t < 40) return m ^ l ^ k;
            if (t < 60) return m & l | m & k | l & k;
            if (t < 80) return m ^ l ^ k;
            return 0;
        }
        public static BigInteger SHA1(FileStream inStream) {
            ulong len = (ulong)inStream.Length * 8;
            uint H0 = 0x67452301, A;
            uint H1 = 0xefcdab89, B;
            uint H2 = 0x98badcfe, C;
            uint H3 = 0x10325476, D;
            uint H4 = 0xc3d2e1f0, E;
            uint[] W = new uint[80];
            int[] BUF = new int[64];
            State state = State.Working;
            while (state != State.Done) {
                Array.Clear(BUF, 0, 64);
                switch (state) {
                    case State.FullConstruct:
                        BUF[0] = 0x80;
                        for (int p = 0; p < 8; p++) {
                            BUF[64 - p - 1] |= (byte)((len >> (p * 8)) & 0xFFFFFFFF);
                        }
                        state = State.Done;
                        break;
                    case State.AppendLen:
                        for (int p = 0; p < 8; p++) {
                            BUF[64 - p - 1] |= (byte)((len >> (p * 8)) & 0xFFFFFFFF);
                        }
                        state = State.Done;
                        break;
                    case State.Working:
                        if (inStream.Position == inStream.Length) {
                            state = State.FullConstruct;
                            continue;
                        }
                        int c;
                        for (int i = 0; i < 64; i++) {
                            c = inStream.ReadByte();
                            if (c == -1) {
                                if (64 - i >= 9) {
                                    BUF[i] = 0x80;
                                    for (int p = 0; p < 8; p++) {
                                        BUF[64 - p - 1] |= (byte)((len >> (p * 8)) & 0xFFFFFFFF);
                                    }
                                    state = State.Done;
                                    break;
                                }
                                else if (64 - i >= 1) {
                                    BUF[i] = 0x80;
                                    state = State.AppendLen;
                                }
                                break;
                            }
                            else
                                BUF[i] = c;
                        }

                        break;
                }
                for (int j = 0; j < 16; j++) {
                    W[j] = (uint)((BUF[4 * j] << 24) | (BUF[4 * j + 1] << 16) | (BUF[4 * j + 2] << 8) | BUF[4 * j + 3]);
                }
                for (int j = 16; j < 80; j++) {
                    W[j] = rol((W[j - 3] ^ W[j - 8] ^ W[j - 14] ^ W[j - 16]), 1);
                }
                A = H0;
                B = H1;
                C = H2;
                D = H3;
                E = H4;
                for (uint j = 0; j < 80; j++) {
                    uint T = rol(A, 5) + Ft(j, B, C, D) + E + W[j] + K(j);
                    E = D;
                    D = C;
                    C = rol(B, 30);
                    B = A;
                    A = T;
                }
                H0 += A;
                H1 += B;
                H2 += C;
                H3 += D;
                H4 += E;
            }
            BigInteger BH0 = new BigInteger(H0);
            BigInteger BH1 = new BigInteger(H1);
            BigInteger BH2 = new BigInteger(H2);
            BigInteger BH3 = new BigInteger(H3);
            BigInteger BH4 = new BigInteger(H4);
            return (BH0 << (32 * 4)) | (BH1 << (32 * 3)) | (BH2 << (32 * 2)) | (BH3 << 32) | BH4;
        }
    }
}
