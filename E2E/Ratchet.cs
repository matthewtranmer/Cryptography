using Cryptography.Generic;

namespace Cryptography.E2E
{
	public class Ratchet
	{
		string root_key;

		public Ratchet(string root_key)
        {
			this.root_key = root_key;
        }

		public string next(string input)
        {
			//derive new value from input
			byte[] opad = new byte[input.Length];
			for (int i = 0; i < input.Length; i++)
            {
				opad[i] = (byte)((byte)input[i] ^ 164);
            }

			//hash appended values to protect against length extention attacks
			string hash = Hash.generateHash(input + root_key);
			hash = Hash.generateHash(hash + opad);

			//first hash value is used as the new root key
			root_key = hash;
			//second hash value is used as the message key
			return Hash.generateHash(hash);
        }
	}

}