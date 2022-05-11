using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;
using Cryptography.Generic;

namespace Cryptography.E2E
{
    class X3DH
    {
        Curves curve;
        public X3DH(Curves curve)
        {
            this.curve = curve;
        }

        //privateSenderID, PrivateSenderEphemeral, publicReceverID, publicSignedPreKey, preKeySignature, ephemeralPreKey   
        public string CalculateSecretSender(BigInteger privateSenderID, BigInteger privateSenderEphemeral, string publicSignedPreKey, string preKeySignature, string publicEphemeralPreKey)
        {
            

            return "";
        }
    }
}
