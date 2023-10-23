using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Crypto
{    
    public class HybridCryptoService : IDisposable
    {
        private RSACryptoService _rsaCryptoService;
        
        public HybridCryptoService(RSACryptoServiceProvider rsaProvider)
        {
            _rsaCryptoService = new RSACryptoService(rsaProvider);
            CheckRsa();
        }

        public HybridCryptoService(string keyXml)
        {
            _rsaCryptoService = new RSACryptoService(keyXml);
            CheckRsa();
        }

        public byte[] Encrypt(byte[] dataToEncrypt)
        {
            if (_rsaCryptoService == null)
                throw new InvalidOperationException();

            var aesService = new AESCryptoService();

            byte[] encryptedDataWithAes = aesService.Encrypt(dataToEncrypt, out string iv);
            byte[] encryptedAesKey = _rsaCryptoService.Encrypt(Convert.FromBase64String(aesService.Key));
            byte[] encryptedAesIv = _rsaCryptoService.Encrypt(Convert.FromBase64String(aesService.IV));

            byte[] mergedEncryptedData = new byte[encryptedDataWithAes.Length + encryptedAesKey.Length + encryptedAesIv.Length];

            Buffer.BlockCopy(encryptedAesKey, 0, mergedEncryptedData, 0, encryptedAesKey.Length);
            Buffer.BlockCopy(encryptedAesIv, 0, mergedEncryptedData, encryptedAesKey.Length, encryptedAesIv.Length);
            Buffer.BlockCopy(encryptedDataWithAes, 0, mergedEncryptedData, encryptedAesKey.Length + encryptedAesIv.Length, encryptedDataWithAes.Length);

            return mergedEncryptedData;
        }

        public byte[] Encrypt(string inputFile)
        {
            if (!File.Exists(inputFile))
                throw new FileNotFoundException(inputFile);

            byte[] fileContent = File.ReadAllBytes(inputFile);

            return Encrypt(fileContent);
        }

        public bool Encrypt(string inputFile, string outputFile)
        {
            if (string.IsNullOrEmpty(inputFile) || string.IsNullOrEmpty(outputFile))
                throw new NoNullAllowedException();

            byte[] encryptedFileBytes = Encrypt(inputFile);
            File.WriteAllBytes(outputFile, encryptedFileBytes);

            return true;
        }

        public byte[] Decrypt(byte[] dataToDecrypt)
        {
            if (_rsaCryptoService == null)
                throw new InvalidOperationException();

            byte[] decryptedAesKey = new byte[_rsaCryptoService.KeySize >> 3];
            byte[] decryptedAesIv = new byte[_rsaCryptoService.KeySize >> 3];
            byte[] decryptedDataWithAes = new byte[dataToDecrypt.Length - decryptedAesKey.Length - decryptedAesIv.Length];

            Buffer.BlockCopy(dataToDecrypt, 0, decryptedAesKey, 0, decryptedAesKey.Length);
            Buffer.BlockCopy(dataToDecrypt, decryptedAesKey.Length, decryptedAesIv, 0, decryptedAesIv.Length);
            Buffer.BlockCopy(dataToDecrypt, decryptedAesKey.Length + decryptedAesIv.Length, decryptedDataWithAes, 0, decryptedDataWithAes.Length);

            var aesKey = _rsaCryptoService.Decrypt(decryptedAesKey);
            var aesIv = _rsaCryptoService.Decrypt(decryptedAesIv);

            var aesService = new AESCryptoService(new AesCryptoServiceProvider() { Key = aesKey, IV = aesIv });

            return aesService.Decrypt(decryptedDataWithAes);
        }

        public byte[] Decrypt(string inputFile)
        {
            if (!File.Exists(inputFile))
                throw new FileNotFoundException(inputFile);

            byte[] fileContent = File.ReadAllBytes(inputFile);

            return Decrypt(fileContent);
        }

        public bool Decrypt(string inputFile, string outputFile)
        {
            if (string.IsNullOrEmpty(inputFile) || string.IsNullOrEmpty(outputFile))
                throw new NoNullAllowedException();

            byte[] encryptedFileBytes = Decrypt(inputFile);
            File.WriteAllBytes(outputFile, encryptedFileBytes);

            return true;
        }

        private void CheckRsa()
        {
            if (_rsaCryptoService.CanOnlyEncrypt)
            {
                this.Dispose();
                throw new Exception("Please use secret key!");
            }
        }

        public void Dispose()
        {
            _rsaCryptoService.Dispose();
            _rsaCryptoService = null;
            GC.SuppressFinalize(this);
        }
    }
}
