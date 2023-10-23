using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Crypto
{
    public class AESCryptoService : IDisposable
    {
        private AesCryptoServiceProvider _provider;
        private readonly string _defaultInitializationVector = "h9GeWnVeV2no3ptirdgXAg==";

        public string Key => Convert.ToBase64String(_provider.Key);
        public string IV => Convert.ToBase64String(_provider.IV);

        public AESCryptoService()
        {
            _provider = new AesCryptoServiceProvider();
            _provider.GenerateKey();
            _provider.GenerateIV();
        }

        public AESCryptoService(AesCryptoServiceProvider provider)
        {
            _provider = provider;
        }

        public AESCryptoService(string base64Key, bool useDefaultIV = true)
        {
            if (!IsBase64String(base64Key, out byte[] key))
                throw new ArgumentException("Key value must be base64 format.");

            _provider = new AesCryptoServiceProvider
            {
                Key = key,
                IV = Convert.FromBase64String(_defaultInitializationVector)
            };

            if (!useDefaultIV)
                _provider.GenerateIV();
        }

        public void SetIV(string base64String)
        {
            if (!IsBase64String(base64String, out byte[] iv))
                throw new ArgumentException("IV value must be base64 format.");

            if (_provider == null)
                throw new InvalidOperationException();

            _provider.IV = iv;
        }

        public byte[] Encrypt(byte[] dataToEncrypt, out string vectorBase64)
        {
            if (_provider == null)
                throw new InvalidOperationException();

            ICryptoTransform encryptor = _provider.CreateEncryptor(_provider.Key, _provider.IV);
            vectorBase64 = Convert.ToBase64String(_provider.IV);

            byte[] encryptedData;
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    cs.Write(dataToEncrypt, 0, dataToEncrypt.Length);
                }
                encryptedData = ms.ToArray();
            }

            return encryptedData;
        }

        public byte[] Encrypt(string inputFile, out string vectorBase64)
        {
            if (!File.Exists(inputFile))
                throw new FileNotFoundException(inputFile);

            byte[] fileContent = File.ReadAllBytes(inputFile);

            return Encrypt(fileContent, out vectorBase64);
        }

        public bool Encrypt(string inputFile, string outputFile, out string vectorBase64)
        {
            if (string.IsNullOrEmpty(inputFile) || string.IsNullOrEmpty(outputFile))
                throw new NoNullAllowedException();

            byte[] encryptedFileBytes = Encrypt(inputFile, out vectorBase64);
            File.WriteAllBytes(outputFile, encryptedFileBytes);

            return true;
        }

        public byte[] Decrypt(byte[] dataToDecrypt)
        {
            if (_provider == null)
                throw new InvalidOperationException();

            ICryptoTransform decryptor = _provider.CreateDecryptor(_provider.Key, _provider.IV);
            byte[] decryptedData;
            using (MemoryStream ms = new MemoryStream(dataToDecrypt))
            {
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    cs.Read(dataToDecrypt, 0, dataToDecrypt.Length);
                }
                decryptedData = ms.ToArray();
            }

            return decryptedData;
        }

        public byte[] Decrypt(string filePath)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException();

            byte[] fileContent = File.ReadAllBytes(filePath);
            return Decrypt(fileContent);
        }

        public bool Decrypt(string inputFile, string outputFile)
        {
            if (string.IsNullOrEmpty(inputFile) || string.IsNullOrEmpty(outputFile))
                throw new NoNullAllowedException();

            byte[] decryptedFileBytes = Decrypt(inputFile);
            File.WriteAllBytes(outputFile, decryptedFileBytes);

            return true;
        }

        private bool IsBase64String(string base64String, out byte[] data)
        {
            data = null;

            if (string.IsNullOrEmpty(base64String) || base64String.Length % 4 != 0
               || base64String.Contains(" ") || base64String.Contains("\t") || base64String.Contains("\r") || base64String.Contains("\n"))
                return false;

            try
            {
                data = Convert.FromBase64String(base64String);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public void Dispose()
        {
            _provider.Dispose();
            _provider = null;
            GC.SuppressFinalize(this);
        }
    }
}
