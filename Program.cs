using System;
using Cryptography.EllipticCurveCryptography;
using System.Numerics;
using System.Linq;

namespace Cryptography
{
    class Program
    {
        private static Random random = new Random();

        public static string RandomString(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        static void Main() 
        {
            BigInteger private_key = BigInteger.Parse("23443554453234345656353468787456342565677884523454678");
            ECC ecc = new ECC(Curves.microsoft_160);

            (string sig, string pub_k) = ecc.generateDSAsignature("", private_key);

            if (ecc.verifyDSAsignature("", sig, pub_k))
            {
                Console.WriteLine("OK");
            }
            else
            {
                Console.WriteLine("BAD");
            }

        }
    }
}
