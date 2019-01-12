using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CRYPTO_PERMUTATION {
    static class PermutationCiphers {
        //RAIL-FENCE        
        public static string RailFenceEncode(string plaintext, int key) {
            string ciphertext = "";
            for (int i = 0; i < key; i++) {
                int j = i;
                while (j < plaintext.Length) {
                    ciphertext += plaintext[j];
                    j += 2 * (key - (j % (key - 1) + 1));
                }
            }
            return ciphertext;
        }
        public static string RailFenceDecode(string ciphertext, int key) {
            StringBuilder plaintext = new StringBuilder(ciphertext);
            int level = 0;
            int len = ciphertext.Length;
            int j = len + 1;
            for (int i = 0; i < len; i++) {
                if (j >= len)
                    j = level++;
                plaintext[j] = ciphertext[i];
                j += 2 * (key - (j % (key - 1) + 1));
            }
            return plaintext.ToString();
        }
        //COLUMN - METHOD
        public static int[] ColumnInitPos(string key) {
            int keyLen = key.Length, minNotUsed = 0, clock = 0;
            int[] f = new int[keyLen];
            bool[] used = new bool[keyLen];

            for (int i = 0; i < keyLen; i++) {
                char minCh = '\xFFFF';
                for (int j = 0; j < keyLen; j++) {
                    if (key[j] < minCh && !used[j]) {
                        minCh = key[j];
                        minNotUsed = j;
                    }
                }
                f[clock++] = minNotUsed;
                used[minNotUsed] = true;
            }
            return f;
        }
        public static string ColumnMethodEncode(string plaintext, string key) {
            string ciphertext = "";
            int[] f = ColumnInitPos(key);
            int keyLen = key.Length;
            int textLen = plaintext.Length;
            for (int i = 0; i < keyLen; i++) {
                int to = f[i];
                while (to < textLen) {
                    ciphertext += plaintext[to];
                    to += keyLen;
                }
            }
            return ciphertext;
        }
        public static string ColumnMethodDecode(string ciphertext, string key) {
            StringBuilder plaintext = new StringBuilder(ciphertext);
            int keyLen = key.Length;
            int[] f = ColumnInitPos(key);
            int textLen = ciphertext.Length;

            int to = textLen + 1;
            int clock = 0;
            for (int i = 0; i < textLen; i++) {
                while (to >= textLen)
                    to = f[clock++];
                plaintext[to] = ciphertext[i];
                to += keyLen;
            }
            return plaintext.ToString();
        }
    }
}
