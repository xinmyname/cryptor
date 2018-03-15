using System;

namespace cryptor
{
    class Program
    {
        public static void Main()
        {
            try
            {
                // IRL, this would have to be read from a secure location
                var key = new byte[] {
                    0x8f, 0xf3, 0x49, 0x9e, 0xcb, 0x30, 0x19, 0xb6, 0xb8, 0x1c, 0x7d, 0x78, 0x22, 0xe1, 0xc8, 0x3e, 
                    0x6a, 0xb5, 0x71, 0x35, 0x43, 0x8a, 0x00, 0x1e, 0xf5, 0xbf, 0xbd, 0xec, 0x4a, 0xfb, 0x35, 0x0b 
                };

                var textCryptor = new TextCryptor(key);

                Console.Write("What's the password? >");
                string password = Console.ReadLine();

                string encryptedPassword = textCryptor.Encrypt(password);

                Console.WriteLine(encryptedPassword);

                string decryptedPassword = textCryptor.Decrypt(encryptedPassword);

                Console.WriteLine(decryptedPassword);
            }
            catch (Exception e)
            {
                Console.WriteLine("Error: {0}", e.Message);
            }
        }
    }
}
