using System.Numerics;
using Cryptography.EllipticCurveCryptography;
using System;

namespace Cryptography
{
    //My implementation of a Merkle-Damgard construction based hash function
    //That produces a 128 bit hash represented by a 32 digit hex string
    static class Hash{
        static UInt32 leftCircularShift(UInt32 operand, int shift){
            return operand << shift | operand >> (32 - shift);
        }

        static string intToHex(UInt32 number){
            string hex = number.ToString("x4");
            int difference = 8 - hex.Length;

            for (int i=0; i<difference; i++){
                hex = "0" + hex;
            }

            return "";
        }

        static UInt32 stringToInt(string data){
            byte[] byte_data = new byte[4];
            
            for (int i=0; i<4; i++){
                byte_data[i] = Convert.ToByte(data[i]);
            }

            return BitConverter.ToUInt32(byte_data, 0);
        }

        static string[] generateBlocks(string data){
            int block_size = 64;

            int total_blocks = (int)Math.Ceiling((double)data.Length/(double)block_size);
            string[] blocks = new string[total_blocks];

            int padding = (total_blocks * block_size) - data.Length;
            for (int i=0; i<padding; i++){
                data += 255;     
            }

            for (int i=0; i<total_blocks; i++){
                blocks[i] = data.Substring(i * block_size, block_size);
            }

            return blocks;
        }

        public static string generateHash(string data){
            //Separate data into 512 bit blocks
            string[] blocks = generateBlocks(data);

            //Set intial internal state values
            UInt32 h0 = 3_456_123_633U; 
            UInt32 h1 = 1_000_562_423U; 
            UInt32 h2 = 4_162_745_346U; 
            UInt32 h3 = 2_245_357_991U; 

            //Iterate over blocks
            for (int block_count=0; block_count<blocks.Length; block_count++){
                UInt32[] words = new UInt32[80];

                //Turn 512 bit block into 16 32 bit words
                for (int i=0; i<16; i++){
                    words[i] = stringToInt(blocks[block_count].Substring(i * 4, 4));
                }

                //Derive 64 words from block values 
                for (int i=16; i<80; i++){
                    words[i] = leftCircularShift(words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16], 1);
                }

                //Set inital round values
                UInt32 a = h0;
                UInt32 b = h1;
                UInt32 c = h2;
                UInt32 d = h3;

                for (int i=0; i<80; i++){
                    //Perform mod 2^32 addition, XORs and other permutations to remove data
                    UInt32 end_addition = a + b + c + d + words[i] + 1_234_934_501;
                    
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
