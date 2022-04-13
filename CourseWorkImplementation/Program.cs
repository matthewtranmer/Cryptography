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
            //⊒
            Console.WriteLine(Hash.generateHash("1"));

            //1e697d33438c59c97587f7f53c83db70
            //

            /*
            BigInteger private_key = BigInteger.Parse("2344355445323434565634523454678");
            ECC ecc = new ECC(Curves.microsoft_160);

            while (true)
            {
                var code = RandomString(100000000);
               
                (string sig, string pub_k) = ecc.generateDSAsignature("edrtkhewhkjlewjhrejkhltr", private_key);

                Console.WriteLine(code);

                if(ecc.verifyDSAsignature(code, sig, pub_k)){
                    break;
                }
            }
            */

        }
    }
}
