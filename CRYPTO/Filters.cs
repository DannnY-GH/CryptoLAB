using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static CRYPTO_STREAM.StreamCiphers;
using static CRYPTO_POLYALP.PolyAlpCiphers;

namespace FILTERS {
    static class Filters {
        public static string numericFilter(string text) {
            const int MAX_LEN = 6;
            string filteredText = "";
            if (text.Length > MAX_LEN)
                text = text.Substring(0, MAX_LEN);
            foreach (char ch in text)
                if (Char.IsDigit(ch))
                    filteredText += ch;
            return filteredText;
        }
        public static string BigUintFilter(string text) {
            const int MAX_BIG_LEN = 300;
            string filteredText = "";
            if (text.Length > MAX_BIG_LEN)
                text = text.Substring(0, MAX_BIG_LEN);
            foreach (char ch in text)
                if (Char.IsDigit(ch))
                    filteredText += ch;
            return filteredText;
        }
        public static string binaryFilter(string text) {
            string filteredText = "";
            if (text.Length > LFSR_BIT_CAPACITY)
                text = text.Substring(0, LFSR_BIT_CAPACITY);
            foreach (char ch in text)
                if (ch - '0' == 0 || ch - '0' == 1)
                    filteredText += ch;
            return filteredText;
        }
        public static string rusAlphaFilter(string text) {
            string filteredText = "";
            foreach (char ch in text)
                if (PosInRusAlp(Char.ToUpper(ch)) != -1)
                    filteredText += Char.ToUpper(ch);
            return filteredText;
        }
        public static string engAlphaFilter(string text) {
            string filteredText = "";
            foreach (char ch in text)
                if (PosInEngAlp(Char.ToUpper(ch)) != -1)
                    filteredText += Char.ToUpper(ch);
            return filteredText;
        }
    }
}
