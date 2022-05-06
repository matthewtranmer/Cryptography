using System.Security.Cryptography;
using System.Text;

public class Encryption
{
    public byte[] initialization_vector { get; set; }

    public void RandomizeInitializationVector()
    {
        initialization_vector = RandomNumberGenerator.GetBytes(initialization_vector.Length);
    }

    public Encryption()
    {
        initialization_vector = RandomNumberGenerator.GetBytes(16); 
    }

    public Encryption(byte[] initialization_vector)
    {
        this.initialization_vector = initialization_vector;
    }

    private SymmetricAlgorithm createEncryptionObj(string key)
    {
        SymmetricAlgorithm algorithm = Aes.Create();
        algorithm.BlockSize = 128;
        algorithm.Key = Encoding.UTF8.GetBytes(key);
        algorithm.IV = initialization_vector;

        return algorithm;
    }

    public Span<byte> AESencrypt(Span<byte> data, string key)
    {
        SymmetricAlgorithm symmetric_algorithm = createEncryptionObj(key);

        using (MemoryStream memory_stream = new MemoryStream())
        {
            using (CryptoStream crypto_stream = new CryptoStream(memory_stream, symmetric_algorithm.CreateEncryptor(), CryptoStreamMode.Write))
            {
                crypto_stream.Write(data);
            }
            return memory_stream.ToArray();
        }
    }

    public Span<byte> AESdecrypt(Span<byte> ciphertext, string key)
    {
        SymmetricAlgorithm symmetric_algorithm = createEncryptionObj(key);
        MemoryStream output_stream = new MemoryStream();

        using (MemoryStream memory_stream = new MemoryStream(ciphertext.ToArray()))
        {
            using (CryptoStream crypto_stream = new CryptoStream(memory_stream, symmetric_algorithm.CreateDecryptor(), CryptoStreamMode.Read))
            {
                crypto_stream.CopyTo(output_stream);
            }
        }
        return output_stream.ToArray();
    }
}
