using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace cryptor
{
    public interface IEncryptText
    {
        string Encrypt(string text);
    }

    public interface IDecryptText
    {
        string Decrypt(string text);
    }

    public class TextCryptor : IEncryptText, IDecryptText
    {
        private readonly byte[] _key;

        public TextCryptor(byte[] key)
        {
            _key = key;
        }

        public string Encrypt(string text)
        {
            var textLength = (byte)text.Length;
            var saltLength = (((text.Length >> 2) + 1) << 3) - 1;
            var saltedText = SaltText(text, saltLength);
            int payloadLen = Encoding.UTF8.GetByteCount(saltedText) + 1;
            var payload = new byte[payloadLen];
            
            payload[0] = textLength;
            Encoding.UTF8.GetBytes(saltedText, 0, saltedText.Length, payload, 1);

            byte[] encryptedPayload;
            
            using (var aes = new AesManaged())
            {
                ICryptoTransform encryptor = aes.CreateEncryptor(_key, aes.IV);

                using (var memStream = new MemoryStream())
                {
                    using (var cryptStream = new CryptoStream(memStream, encryptor, CryptoStreamMode.Write))
                        cryptStream.Write(payload, 0, payloadLen);

                    byte[] cipherBytes = memStream.ToArray();
                    encryptedPayload = aes.IV.Concat(cipherBytes).ToArray();
                }
            }

            return Convert.ToBase64String(encryptedPayload);
        }

        public string Decrypt(string text)
        {
            byte[] encryptedPayload = Convert.FromBase64String(text);
            byte[] decryptedPayload;

            using (var aes = new AesManaged())
            {
                int ivLength = aes.BlockSize / 8;
                byte[] iv = encryptedPayload.Take(ivLength).ToArray();
                byte[] cipherBytes = encryptedPayload.Skip(ivLength).ToArray();

                ICryptoTransform decryptor = aes.CreateDecryptor(_key, iv);

                using (var memStream = new MemoryStream(cipherBytes))
                using (var decryptedStream = new MemoryStream())
                {
                    using (var cryptStream = new CryptoStream(memStream, decryptor, CryptoStreamMode.Read))
                        cryptStream.CopyTo(decryptedStream);

                    decryptedPayload = decryptedStream.ToArray();
                }                
            }

            int textLength = decryptedPayload[0];
            string saltedText = Encoding.UTF8.GetString(decryptedPayload, 1, decryptedPayload.Length - 1);
            return saltedText.Substring(0, textLength);
        }

        private static char[] TypableChars = {
            '`', '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=',
            '~', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+',
            'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']',
            'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '|',
            'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';',
            'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':',
            'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 
            'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<', '>', '?'            
        };

        private static string GetRandomText(int length)
        {
            var text = new StringBuilder(length);
            var rng = new Random();
            
            for (int i = 0; i < length; i++)
                text.Append(TypableChars[rng.Next(0, TypableChars.Length)]);

            return text.ToString();
        }

        private static string SaltText(string text, int length)
        {
            if (text.Length > length)
                throw new ArgumentException("Text length exceeded salted length.", nameof(length));

            var saltedText = new StringBuilder(text, length);

            saltedText.Append(GetRandomText(length - text.Length));

            return saltedText.ToString();
        }
    }
}
