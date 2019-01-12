using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CRYPTO_POLYALP {
    static class PolyAlpCiphers {
        const int RUS_ALP_SIZE = 33, INF = (int)1e9;
        const string RUS_ALP = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";
        const int ENG_ALP_SIZE = 26;
        const string ENG_ALP = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        static char F(int ch, int k) {
            return RUS_ALP[(ch + k) % RUS_ALP_SIZE];
        }
        public static int PosInRusAlp(char letter) {
            return RUS_ALP.IndexOf(letter.ToString(), 0);
        }
        public static int PosInEngAlp(char letter) {
            return ENG_ALP.IndexOf(letter.ToString(), 0);
        }
        //VIGENER
        public static string VigenerEncode(string text, string key) {
            string cipher = "";
            int i = 0, j = 0, offset;
            while (i != text.Length) {
                offset = PosInRusAlp(text[i]);
                if (offset != -1) {
                    cipher += F(offset, PosInRusAlp(key[j]));
                    j = (j + 1) % key.Length;
                }
                else
                    cipher += text[i];
                i++;
            }
            return cipher;
        }
        public static string VigenerDecode(string text, string key) {
            string plainText = "";
            int i = 0, j = 0, offset;
            while (i != text.Length) {
                offset = PosInRusAlp(text[i]);
                if (offset != -1) {
                    plainText += F(offset, RUS_ALP_SIZE - PosInRusAlp(key[j]));
                    j = (j + 1) % key.Length;
                }
                else
                    plainText += text[i];
                i++;
            }
            return plainText;
        }
        const int MAX_KEY_LENGTH = 20;
        private static void KMP(string s, int startPos, ref int[] stats) {
            int[] p = new int[s.Length];
            p[0] = 0;
            for (int i = 1; i < s.Length; i++) {
                int j = p[i - 1];
                while (j > 0 && s[j] != s[i])
                    j = p[j - 1];
                if (s[i] == s[j])
                    j++;
                p[i] = j;
                //FACTORING
                if (p[i] > 2) {
                    int factor = i - p[i] + 1;
                    for (int k = 1; k < factor; k++)
                        if (factor % k == 0)
                            if (k <= MAX_KEY_LENGTH)
                                stats[k]++;
                }
            }
        }
        class Comp : IComparer<KeyValuePair<int, int>> {
            public int Compare(KeyValuePair<int, int> x, KeyValuePair<int, int> y) {
                if (y.Value > x.Value)
                    return 1;
                else if ((y.Value == x.Value) && (y.Key > x.Key))
                    return 1;
                else
                    return -1;
            }
        }
        public static List<string> KasiskiTest(string text) {
            List<string> retKeys = new List<string>();
            string KEY = "";
            int[] factorStats = new int[MAX_KEY_LENGTH + 1];
            //GAIN STATS
            for (int i = 0; i < text.Length; i++)
                KMP(text.Substring(i, text.Length - i), i, ref factorStats);
            //FREQUERENCY ANALYSIS
            List<KeyValuePair<int, int>> keys = new List<KeyValuePair<int, int>>();
            for (int i = 3; i <= MAX_KEY_LENGTH; i++)
                keys.Add(new KeyValuePair<int, int>(i, factorStats[i]));
            keys.Sort(new Comp());
            int[] freq = new int[RUS_ALP_SIZE];
            for (int i = 0; i < keys.Count; i++) {
                int delta = keys[i].Key;
                //DEFINE EACH CHARACTER OF KEY-PHRASE
                for (int p = 0; p < delta; p++) {
                    int j = 0, size = 0;
                    while (j + p < text.Length) {
                        freq[PosInRusAlp(text[j + p])]++;
                        j += delta;
                        size++;
                    }
                    //FIND MAX 
                    int maxLetter = 15, maxFreq = -INF;
                    for (int k = 0; k < RUS_ALP_SIZE; k++) {
                        if (freq[k] > maxFreq) {
                            maxFreq = freq[k];
                            maxLetter = k;
                        }
                        freq[k] = 0;
                    }
                    KEY += RUS_ALP[(maxLetter - 15 + RUS_ALP_SIZE) % RUS_ALP_SIZE];
                }
                retKeys.Add(KEY);
                KEY = "";
            }
            return retKeys;
        }
    }
}
