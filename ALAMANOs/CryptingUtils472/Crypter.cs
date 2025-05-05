using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptingUtils
{
    public class Crypter
    {
        private static readonly byte[] DefaultSalt = new byte[] { 0x43, 0x72, 0x79, 0x70, 0x74, 0x69, 0x6E, 0x67, 0x55, 0x74, 0x69, 0x6C, 0x73, 0x53, 0x61, 0x6C };
        private static readonly int KeySize = 256;
        private static readonly int BlockSize = 128;
        private static readonly int DerivationIterations = 50000;

        public static string Encrypt(string plainText, byte[] key)
        {
            if (string.IsNullOrEmpty(plainText))
                return plainText;

            try
            {
                byte[] saltBytes = DefaultSalt;
                byte[] ivBytes = GenerateRandomEntropy();
                byte[] passwordBytes = key;

                using (Rfc2898DeriveBytes derivedKey = new Rfc2898DeriveBytes(passwordBytes, saltBytes, DerivationIterations))
                {
                    byte[] keyBytes = derivedKey.GetBytes(KeySize / 8);
                    using (RijndaelManaged symmetricKey = new RijndaelManaged())
                    {
                        symmetricKey.BlockSize = BlockSize;
                        symmetricKey.Mode = CipherMode.CBC;
                        symmetricKey.Padding = PaddingMode.PKCS7;

                        using (ICryptoTransform encryptor = symmetricKey.CreateEncryptor(keyBytes, ivBytes))
                        {
                            using (MemoryStream memoryStream = new MemoryStream())
                            {
                                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                                {
                                    using (StreamWriter writer = new StreamWriter(cryptoStream))
                                    {
                                        writer.Write(plainText);
                                    }
                                    
                                    byte[] cipherTextBytes = memoryStream.ToArray();
                                    byte[] combinedBytes = new byte[ivBytes.Length + cipherTextBytes.Length];
                                    Buffer.BlockCopy(ivBytes, 0, combinedBytes, 0, ivBytes.Length);
                                    Buffer.BlockCopy(cipherTextBytes, 0, combinedBytes, ivBytes.Length, cipherTextBytes.Length);
                                    
                                    return Convert.ToBase64String(combinedBytes);
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                throw new CryptographicException("Encryption failed", ex);
            }
        }

        public static string Decrypt(string cipherText, byte[] key)
        {
            if (string.IsNullOrEmpty(cipherText))
                return cipherText;

            try
            {
                byte[] saltBytes = DefaultSalt;
                byte[] combinedBytes = Convert.FromBase64String(cipherText);
                
                byte[] ivBytes = new byte[16];
                byte[] cipherTextBytes = new byte[combinedBytes.Length - ivBytes.Length];
                
                Buffer.BlockCopy(combinedBytes, 0, ivBytes, 0, ivBytes.Length);
                Buffer.BlockCopy(combinedBytes, ivBytes.Length, cipherTextBytes, 0, cipherTextBytes.Length);
                
                byte[] passwordBytes = key;

                using (Rfc2898DeriveBytes derivedKey = new Rfc2898DeriveBytes(passwordBytes, saltBytes, DerivationIterations))
                {
                    byte[] keyBytes = derivedKey.GetBytes(KeySize / 8);
                    
                    using (RijndaelManaged symmetricKey = new RijndaelManaged())
                    {
                        symmetricKey.BlockSize = BlockSize;
                        symmetricKey.Mode = CipherMode.CBC;
                        symmetricKey.Padding = PaddingMode.PKCS7;
                        
                        using (ICryptoTransform decryptor = symmetricKey.CreateDecryptor(keyBytes, ivBytes))
                        {
                            using (MemoryStream memoryStream = new MemoryStream(cipherTextBytes))
                            {
                                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                                {
                                    using (StreamReader reader = new StreamReader(cryptoStream))
                                    {
                                        return reader.ReadToEnd();
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (CryptographicException)
            {
                throw new CryptographicException("Decryption failed. The cipher text may have been tampered with, or the encryption key is incorrect.");
            }
            catch (FormatException)
            {
                throw new FormatException("Decryption failed. The cipher text is not in the correct format.");
            }
            catch (Exception ex)
            {
                throw new CryptographicException("Decryption failed due to an unexpected error.", ex);
            }
        }

        private static byte[] GenerateRandomEntropy()
        {
            byte[] randomBytes = new byte[16];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            return randomBytes;
        }
        
        public static byte[] GenerateKey(string passphrase)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(Encoding.UTF8.GetBytes(passphrase));
            }
        }
    }
}