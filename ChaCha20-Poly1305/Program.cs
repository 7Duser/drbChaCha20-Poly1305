using System.Security.Cryptography;
using System.Text;

namespace ChaCha20_Poly1305;

public static class Program
{
    public static void Main()
    {

        byte[] key = new byte[bChaCha20Poly1305.KeySize];
        RandomNumberGenerator.Fill(key);
        byte[] nonce = new byte[bChaCha20Poly1305.NonceSize];
        RandomNumberGenerator.Fill(nonce);

        const string message = "insane text that i must hide";
        byte[] plaintext = Encoding.UTF8.GetBytes(message);
        byte[] associatedData = "some extra data"u8.ToArray();

        Console.WriteLine($"Text: \"{message}\"");
        Console.WriteLine();

        Console.WriteLine("Encrypting");
        (byte[] ciphertext, byte[] tag) = bChaCha20Poly1305.Encrypt(key, nonce, plaintext, associatedData);

        Console.WriteLine($"Ciphertext: {Convert.ToHexString(ciphertext)}");
        Console.WriteLine($"Auth Tag: {Convert.ToHexString(tag)}");
        Console.WriteLine();

        Console.WriteLine("Decrypting");
        var (decryptedBytes, success) = bChaCha20Poly1305.Decrypt(key, nonce, ciphertext, tag, associatedData);

        if (success)
        {
            string decryptedMessage = Encoding.UTF8.GetString(decryptedBytes);
            Console.WriteLine($"Decrypted message: \"{decryptedMessage}\"");
        }
        else
        {
            Console.WriteLine("Whoops something broke");
        }
        Console.WriteLine();
        
        Console.WriteLine("Tampering Attempt");
        tag[0] ^= 0xFF;

        (byte[]? tamperedBytes, bool tamperedSuccess) = bChaCha20Poly1305.Decrypt(key, nonce, ciphertext, tag, associatedData);

        if (!tamperedSuccess)
        {
            Console.WriteLine($"Returned bytes: {(tamperedBytes == null! ? "null" : "not null")}");
        }
        else
        {
            Console.WriteLine("Whoops something broke, tampering was not detected");
        }
    }
}