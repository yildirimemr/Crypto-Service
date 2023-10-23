# Crypto Library
Crypto library is a file encryption library designed using the C# software language on the .NET 4.0 Framework.

## Features
1. There are no third party library dependencies.
2. It includes RSA (Asymmetric), AES (Symmetric), and RSA-AES (Hybrid) encryption methods.
3. The user can encrypt with any method he/she wishes, depending on his/her scenario (file size, security level, etc.).
4. The user can perform the encryption process either with the KEYs he/she determines or with the KEYs determined at random.

## Encryption Methods
1. AES (Symmetric) Encryption Method
* It performs both encryption and decryption operations via a single 128-bit key.
* It is one of the fastest encryption methods. Thus, large data can be quickly encrypted.
* Auxiliary vector information is also required in decryption processes. If the user wishes, he/she can generate this vector randomly during encryption or use the fixed vector in the class.
* The key used for encryption and decryption is the same.
* It is the decryption method with the lowest security level.
2. RSA (Asymmetric) Encryption Method
* There are two KEYs with the bit size specified by the user.
* The data to be encrypted is directly proportional to the bit size of the KEY to be encrypted. The larger the file to be encrypted, the larger the key with the bit value should be generated.
* Therefore, it is the slowest encryption method in terms of speed. It is not recommended to use it on big data.
* With this method, the user will have two KEYs. While those who have the Public KEY will only be able to encrypt, those who have the Private KEY will be able to perform both encryption and decryption.
* It is the encryption method with the highest security level.
3. RSA-AES (Hybrid) Encryption Method
* This method is used as a mixture of AES and RSA methods.
* It is a method developed to encrypt large data more securely and not to depend on a single KEY.
* When encrypting data, first a random AES KEY is generated. The generated AES KEY is encrypted with the specified RSA Public KEY and written to the beginning of the file. First of all, the AES KEY at the beginning of the data to be decrypted is decrypted with the specified RSA Private KEY, and the rest of the file is decrypted with the decrypted AES KEY.
* Each AES KEY produced is produced specifically for the encrypted data. Therefore, even if the RSA KEYs of each data are the same, the AES KEYs will remain specific to the data.
* The biggest advantage of this method is that transactions are carried out through two RSA KEYs rather than relying on a single KEY.
* Its security rating is more secure than AES and weaker than RSA.

## Security Levels
- RSA (Asymmetric) Encryption Method > RSA-AES (Hybrid) Encryption Method > AES (Symmetric) Encryption Method

## Working Speed Levels
- AES (Symmetric) Encryption Method > RSA-AES (Hybrid) Encryption Method > RSA (Asymmetric) Encryption Method

## Usage
- AES (Symmetric) Encryption Method
```
var aesService = new AESCryptoService(); // or new AESCryptoService(myBase64StringKey);

Console.WriteLine($"AES KEY: {aesService.Key}, AES IV: {aesService.IV}");

var encryptedData = aesService.Encrypt(new byte[] myInputByteArray, out string initialVector); // 1. yöntem
var encryptedData = aesService.Encrypt("inputFilePath", out string initialVector); // 2. yöntem
var encryptedData = aesService.Encrypt("inputFilePath", "outputFilePath", out string initialVector); // 3. yöntem

var decryptedData = aesService.Decrypt(new byte[] myEncryptedByteArray); // 1. yöntem
var decryptedData = aesService.Decrypt("encryptedFilePath"); // 2. yöntem
var decryptedData = aesService.Decrypt("encryptedFilePath", "outputFilePath"); // 3. yöntem
```
- RSA (Asymmetric) Encryption Method
```
var rsaService = new RSACryptoService(); // or new RSACryptoService(MyKeyBitSize) or new RSACryptoService(myKeyXml)

Console.WriteLine($"Only Encrypt: {rsaService.CanOnlyEncrypt}, RSA Public Key: {rsaService.PublicKey}, RSA Private Key: {rsaService.SecretKey}");

var encryptedData = rsaService.Encrypt(new byte[] myInputByteArray);
var encryptedData = rsaService.Encrypt("inputFilePath");
var encryptedData = rsaService.Encrypt("inputFilePath", "outputFilePath");

var decryptedData = rsaService.Decrypt(new byte[] myEncryptedByteArray);
var decryptedData = rsaService.Decrypt("encryptedFilePath");
var decryptedData = rsaService.Decrypt("encryptedFilePath", "outputFilePath");
```
- RSA-AES (Hybrid) Encryption Method
```
var hybridService = new HybridCryptoService(myRsaKeyXML);

var encryptedData = rsaService.Encrypt(new byte[] myInputByteArray);
var encryptedData = rsaService.Encrypt("inputFilePath");
var encryptedData = rsaService.Encrypt("inputFilePath", "outputFilePath");

var decryptedData = rsaService.Decrypt(new byte[] myEncryptedByteArray);
var decryptedData = rsaService.Decrypt("encryptedFilePath");
var decryptedData = rsaService.Decrypt("encryptedFilePath", "outputFilePath");
```

## Authors
* **Emre Yıldırım** - [GitHub](https://github.com/yildirimemr)