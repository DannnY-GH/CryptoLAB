using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace CRYPTO_MATH {
    static class Math {
        public static long powmod(long a, long b, long p) {
            long res = 1;
            while (b > 0) {
                if ((b & 1) == 1)
                    res = (res * a % p);
                a = a * a % p;
                b >>= 1;
            }
            return res;
        }
        public static uint rol(uint x, int bits) {
            return (x << bits) | (x >> (32 - bits));
        }
        public static ulong reverseBits(ulong x, int capacity) {
            ulong rev = 0;
            for (int i = 0; i < capacity - 1; i++, rev <<= 1, x >>= 1)
                rev |= (x & 1);
            return rev;
        }
        public static List<long> generator(long p) {
            List<long> fact = new List<long>();
            List<long> ret = new List<long>();
            long phi = p - 1, n = phi;
            for (int i = 2; i * i <= n; ++i)
                if (n % i == 0) {
                    fact.Add(i);
                    while (n % i == 0)
                        n /= i;
                }
            if (n > 1)
                fact.Add(n);
            for (long g = 2; g < p; ++g) {
                bool ok = true;
                for (int i = 0; i < fact.Count && ok; ++i)
                    ok &= powmod(g, phi / fact[i], p) != 1;
                if (ok)
                    ret.Add(g);
            }
            return ret;
        }
        public static long gcd(long a, long b) {
            return (b > 0) ? gcd(b, a % b) : a;
        }
        public static bool ferma(long x) {
            if (x == 2)
                return true;
            Random rand = new Random();
            for (int i = 0; i < 1000; i++) {
                long a = (rand.Next() % (x - 2)) + 2;
                if (gcd(a, x) != 1)
                    return false;
                if (powmod(a, x - 1, x) != 1)
                    return false;
            }
            return true;
        }

        public static long extgcd(long a, long b, ref long x, ref long y) {
            if (a == 0) {
                x = 0; y = 1;
                return b;
            }
            long x1 = 0, y1 = 0;
            long d = extgcd(b % a, a, ref x1, ref y1);
            x = y1 - (b / a) * x1;
            y = x1;
            return d;
        }
        public static long Rev(long a, long p) {
            long x = 0, y = 0;
            extgcd(a, p, ref x, ref y);
            return (x % p + p) % p;
        }
        //RSA-DS
        public static BigInteger BIGextgcd(BigInteger a, BigInteger b, ref BigInteger x, ref BigInteger y) {
            if (a == 0) {
                x = 0; y = 1;
                return b;
            }
            BigInteger x1 = 0, y1 = 0;
            BigInteger d = BIGextgcd(b % a, a, ref x1, ref y1);
            x = y1 - (b / a) * x1;
            y = x1;
            return d;
        }
        public static BigInteger BIGpowmod(BigInteger a, BigInteger b, BigInteger p) {
            BigInteger res = 1;
            while (b > 0) {
                if ((b & 1) == 1)
                    res = (res * a % p);
                a = a * a % p;
                b >>= 1;
            }
            return res;
        }
        public static BigInteger BIGgcd(BigInteger a, BigInteger b) {
            return (b > 0) ? BIGgcd(b, a % b) : a;
        }
        public static bool BigIntFerma(BigInteger x) {
            if (x == 2)
                return true;
            Random rand = new Random();
            for (BigInteger i = 0; i < 100; i++) {
                BigInteger a = (rand.Next() % (x - 2)) + 2;
                if (BIGgcd(a, x) != 1)
                    return false;
                if (BIGpowmod(a, x - 1, x) != 1)
                    return false;
            }
            return true;
        }
    }
}
