using System;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
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

        public string Encrypt(string plainText)
        {
            var payload = EncodePayload(plainText);
            byte[] encryptedPayload;
            
            using (var aes = new AesManaged())
            {
                ICryptoTransform encryptor = aes.CreateEncryptor(_key, aes.IV);

                using (var memStream = new MemoryStream())
                {
                    using (var cryptStream = new CryptoStream(memStream, encryptor, CryptoStreamMode.Write))
                        cryptStream.Write(payload, 0, payload.Length);

                    byte[] cipherBytes = memStream.ToArray();
                    encryptedPayload = aes.IV.Concat(cipherBytes).ToArray();
                }
            }

            return Convert.ToBase64String(encryptedPayload);
        }

        public string Decrypt(string cipherText)
        {
            byte[] encryptedPayload = Convert.FromBase64String(cipherText);
            byte[] payload;

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

                    payload = decryptedStream.ToArray();
                }                
            }

            return DecodePayload(payload);
        }

        private byte[] EncodePayload(string text)
        {
            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream))
            {
                byte[] textBytes = Encoding.UTF8.GetBytes(text);
                int version = 1;
                int length = textBytes.Length;

                writer.Write(version);
                writer.Write(length);
                writer.Write(textBytes);

                return stream.ToArray();
            }
        }

        private string DecodePayload(byte[] payload)
        {
            using (var stream = new MemoryStream(payload))
            using (var reader = new BinaryReader(stream))
            {
                int version = reader.ReadInt32();
                int length = reader.ReadInt32();
                byte[] textBytes = reader.ReadBytes(length);

                return Encoding.UTF8.GetString(textBytes);
            }
        }
    }
}
