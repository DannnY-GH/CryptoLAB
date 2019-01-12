using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CRYPTO_STREAM {
    static class StreamCiphers {
        //LFSR1
        //x26 + x8 + x7 + x + 1 - BIT_CAPACITY = 26
        public const int LFSR_BIT_CAPACITY = 26;
        //const int BIT_CAPACITY = 23;
        public static byte[] LFSREncode(ref byte[] data, string initReg) {
            uint reg = 0;
            int i;
            for (i = 0; i < LFSR_BIT_CAPACITY; i++)
                reg |= ((uint)(initReg[LFSR_BIT_CAPACITY - i - 1] - '0') << i);
            uint calc;
            //GEN TILL 31st bit
            for (i = LFSR_BIT_CAPACITY; i < 32; i++) {
                calc = ((reg >> 25) ^ (reg >> 7) ^ (reg >> 6) ^ (reg)) & 1;
                reg <<= 1;
                reg |= calc;
            }
            uint regCopy = reg;
            for (i = 0; i < data.Length; i++) {
                data[i] ^= (byte)(reg >> 24);
                //x26 + x8 + x7 + x + 1 - BIT_CAPACITY = 26
                for (int j = 0; j < 8; j++) {
                    calc = ((reg >> 25) ^ (reg >> 7) ^ (reg >> 6) ^ (reg)) & 1;
                    reg <<= 1;
                    reg |= calc;
                }
            }
            //DISPLAY KEY
            /*
            tbLFSRKey.Clear();
            const long KEY_DISPLAY_AMT = 128;
            int till = (int)Math.Min(KEY_DISPLAY_AMT, data.Length * 8L);
            char[] buf = new char[till];
            reg = regCopy;
            for (i = 0; i < till; i++) {
                buf[i] = (char)(((reg >> 31) & 1) + '0');
                calc = ((reg >> 25) ^ (reg >> 7) ^ (reg >> 6) ^ (reg)) & 1;
                reg <<= 1;
                reg |= calc;
            }
            tbLFSRKey.Text = new string(buf, 0, till);
            */
            return data;
        }
        //RC4
        public static void RC4Encrypt(ref byte[] data, string U) {
            byte[] S = new byte[256];
            byte[] UKey = new byte[256];
            for (int l = 0; l <= 255; l++) {
                S[l] = (byte)l;
            }
            string[] tokens = U.Split();
            byte buf;
            int size = 0;
            foreach (string item in tokens) {
                if (Byte.TryParse(item, out buf)) {
                    UKey[size++] = buf;
                }
            }
            int i = 0;
            int j = 0;
            for (i = 0; i < 256; i++) {
                j = (j + S[i] + UKey[i % size]) % 256;
                byte tmp = S[i];
                S[i] = S[j];
                S[j] = tmp;
            }
            byte K;
            i = 0;
            j = 0;
            //XOR and KEY
            /*
            tbLFSRKey.Clear();
            const long KEY_DISPLAY_AMT = 128;
            int till = (int)Math.Min(KEY_DISPLAY_AMT, data.Length * 8L);
            string[] keyBuf = new string[till];
            int p = 0;
            for (int k = 0; k < data.Length; k++) {
                i = (i + 1) % 256;
                j = (j + S[i]) % 256;
                byte tmp = S[i];
                S[i] = S[j];
                S[j] = S[i];
                K = S[(S[i] + S[j]) % 256];
                data[k] ^= K;
                if (p < KEY_DISPLAY_AMT)
                    keyBuf[p++] = K.ToString();
            }
            tbLFSRKey.Text = String.Join(" ", keyBuf);
            */
        }
    }
}
