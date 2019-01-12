using System.IO;
using static CRYPTO_MATH.Math;

namespace CRYPTO_PUBLIC {
    static class PublicKeyCiphers {
        public static void ElgamalEncrypt(FileStream inStream, FileStream outStream, long p, long x, long k, long g) {
            long y = powmod(g, x, p);
            //Ko = (p, g, y)
            //Kc = (x)
            long a, b;
            long len = inStream.Length;
            for (int i = 0; i < len;) {
                for (int j = 0; j < p && i < len; ++i, ++j) {
                    int m = inStream.ReadByte();
                    a = powmod(g, k, p);
                    b = (powmod(y, k, p) * m) % p;
                    outStream.WriteByte((byte)((a & 0xFF00) >> 8));
                    outStream.WriteByte((byte)(a & 0xFF));
                    outStream.WriteByte((byte)((b & 0xFF00) >> 8));
                    outStream.WriteByte((byte)(b & 0xFF));
                }
            }
        }
        public static void ElgamalDecrypt(FileStream inStream, FileStream outStream, long x, long p) {
            for (int i = 0; i < inStream.Length / 4; i++) {
                long a = inStream.ReadByte();
                byte al = (byte)inStream.ReadByte();
                a = (a << 8) | al;
                long b = inStream.ReadByte();
                byte bl = (byte)inStream.ReadByte();
                b = (b << 8) | bl;
                a = powmod(a, x, p);
                a = Rev(a, p);
                long m = (b * a) % p;
                outStream.WriteByte((byte)m);
            }
        }
    }
}
