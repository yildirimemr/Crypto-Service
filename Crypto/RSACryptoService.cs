using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Crypto
{
    public class RSACryptoService : IDisposable
    {
        private RSACryptoServiceProvider _provider;
        public bool CanOnlyEncrypt => _provider.PublicOnly;
        public string PublicKey => _provider.ToXmlString(false);
        public string SecretKey => _provider.ToXmlString(true);
        public int KeySize => _provider.KeySize;

        public RSACryptoService()
        {
            _provider = new RSACryptoServiceProvider();
        }

        public RSACryptoService(int keySize)
        {
            _provider = new RSACryptoServiceProvider(keySize);
        }

        public RSACryptoService(RSACryptoServiceProvider provider)
        {
            _provider = provider;
        }

        public RSACryptoService(string keyXml)
        {
            _provider = new RSACryptoServiceProvider();
            _provider.FromXmlString(keyXml);
        }

        public byte[] Encrypt(byte[] dataToEncrypt)
        {
            if (_provider == null)
                throw new InvalidOperationException();

            return _provider.Encrypt(dataToEncrypt, true);
        }

        public byte[] Encrypt(string filePath)
        {
            if(!File.Exists(filePath))
                throw new FileNotFoundException();

            byte[] fileContent = File.ReadAllBytes(filePath);
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
            if (_provider == null)
                throw new InvalidOperationException();

            return _provider.Decrypt(dataToDecrypt, true);
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

        public void Dispose()
        {
            _provider.Dispose();
            _provider = null;
            GC.SuppressFinalize(this);
        }
    }
}
