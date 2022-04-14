using System;
using System.Text;
using System.Collections.Generic;

namespace Cryptography
{
    //My implementation of a Merkle-Damgard construction based hash function
    //That produces a 128 bit hash represented by a 32 digit hex string
    static class Hash{
        static uint leftCircularShift(uint operand, int shift){
            return operand << shift | operand >> (32 - shift);
        }

        static uint stringToInt(string data){
            byte[] byte_data = new byte[4];
            
            for (int i=0; i<4; i++){
                byte_data[i] = Encoding.UTF8.GetBytes(data[i].ToString())[0];
                //byte_data[i] = Convert.ToByte(data[i], );
            }

            return BitConverter.ToUInt32(byte_data, 0);
        }

        //split data into 512 bit blocks and add padding if necessary
        public static byte[,] generateBlocks(string data){
            int block_size = 64;

            byte[] bytes = Encoding.UTF8.GetBytes(data);
            int total_blocks = (int)Math.Ceiling((double)bytes.Length/(double)block_size);

            byte[,] blocks = new byte[total_blocks, 64];
            int block_count = 0;

            for (int i = 0; i < total_blocks; i++)
            {
                int iterations = block_size;
                if (bytes.Length - i * block_size < block_size)
                {
                    iterations = bytes.Length - (bytes.Length / block_size * block_size); //remanders
                }

                for (int x=0; x < iterations; x++)
                {
                    blocks[i, x] = bytes[block_count];
                    block_count++;
                }
            }

            return blocks;
        }

        public static string generateHash(string data)
        {
            //Separate data into 512 bit blocks
            byte[,] blocks = generateBlocks(data);

            //Set intial internal state values
            uint h0 = 3_456_123_633U;
            uint h1 = 1_000_562_423U;
            uint h2 = 4_162_745_346U;
            uint h3 = 2_245_357_991U;

            //Iterate over blocks
            for (int block_count = 0; block_count < blocks.GetLength(0); block_count++)
            {
                uint[] words = new uint[80];

                //Turn 512 bit block into 16, 32 bit words
                for (int i = 0; i < 16; i++)
                {
                    byte[] bytes = new byte[4];
                    for(int j = 0; j < 4; j++)
                    {
                        bytes[j] = blocks[block_count, i*4 + j];
                    }
                    words[i] = BitConverter.ToUInt32(bytes, 0);
                }

                //Derive an extra 64 words from block values 
                for (int i = 16; i < 80; i++)
                {
                    words[i] = leftCircularShift(words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16], 1);
                }

                //Set inital round values
                uint a = h0;
                uint b = h1;
                uint c = h2;
                uint d = h3;

                for (int i = 0; i < 80; i++)
                {
                    //Perform mod 2^32 addition, XORs and other permutations to remove data
                    uint end_addition = a + b + c + d + words[i] + 1_234_934_501;

                    d = leftCircularShift(b, 19) ^ c;
                    b = a ^ b;
                    c = leftCircularShift(b, 15);

                    a = end_addition;
                }

                //Add round values onto total internal state values
                h0 += a;
                h1 += b;
                h2 += c;
                h3 += d;
            }

            //Combine internal state in hex to produce hash
            string hash = h0.ToString("x8") + h1.ToString("x8") + h2.ToString("x8") + h3.ToString("x8");
            return hash;
        }
    } 
}
