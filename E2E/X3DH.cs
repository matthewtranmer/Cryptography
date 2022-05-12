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
        ECC ecc;

        public X3DH(Curves curve)
        {
            ecc = new ECC(curve);
        }

        //privateSenderID, publicSenderID,   
        public string CalculateSecretSender(BigInteger privateSenderID, string publicSignedPreKey, BigInteger privateEphemeralKey, string publicSenderID, string publicOneTimePreKey, string preKeySignature)
        {
            if (!ecc.verifyDSAsignature(publicSignedPreKey, preKeySignature, publicSenderID))
            {
                throw new Exception("Pre keys have been tampered with");
            }

            string component1 = ecc.ECDH(privateSenderID, publicSignedPreKey);
            string component2 = ecc.ECDH(privateEphemeralKey, publicSenderID);
            string component3 = ecc.ECDH(privateEphemeralKey, publicSignedPreKey);
            string component4 = ecc.ECDH(privateEphemeralKey, publicOneTimePreKey);

            string shared_key = Hash.generateHash(component1);
            shared_key = Hash.generateHash(shared_key + component2);
            shared_key = Hash.generateHash(shared_key + component3);
            shared_key = Hash.generateHash(shared_key + component4);

            return shared_key;
        }

        public string CalculateSecretReciever(BigInteger privateSignedPreKey, string publicSenderID, BigInteger privateRecieverID, string publicEphemeralKey, BigInteger privateOneTimePreKey)
        {
            string component1 = ecc.ECDH(privateSignedPreKey, publicSenderID);
            string component2 = ecc.ECDH(privateRecieverID, publicEphemeralKey);
            string component3 = ecc.ECDH(privateSignedPreKey, publicEphemeralKey);
            string component4 = ecc.ECDH(privateOneTimePreKey, publicEphemeralKey);

            string shared_key = Hash.generateHash(component1);
            shared_key = Hash.generateHash(shared_key + component2);
            shared_key = Hash.generateHash(shared_key + component3);
            shared_key = Hash.generateHash(shared_key + component4);

            return shared_key;
        }
    }
}
