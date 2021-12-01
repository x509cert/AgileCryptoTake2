using System;
using System.Text;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace PracticalAgileCrypto
{
    class AgileCrypto
    {
        // salt size is byte count, not bit count
        private const int SALTSIZE = 128 / 8;

        //This is for testing purposes - 4 versions
        public enum Version
        {
            VERSION_1 = 1,
            VERSION_2 = 2,
            VERSION_3 = 3,
            VERSION_4 = 4,
            VERSION_LATEST = VERSION_4
        };

        // DELIM is used to delimit the items in the resulting string
        private char DELIM = '|';

        private SymmetricAlgorithm  _symCrypto;
        private HMAC                _hMac;
        private DeriveBytes         _keyDerivation;
        private int                 _iterationCount;
        private Version             _ver;
        private byte[]              _salt;
        private byte[]              _keyMaterial;

        public AgileCrypto(byte[] keyMaterial,
                   Version ver = Version.VERSION_LATEST)
        {
            
        }

        public AgileCrypto(byte[] keyMaterial,
                           byte[] salt,
                           Version ver = Version.VERSION_LATEST)
        {
            // if the salt is non-existant, then create one
            if (salt.Length == 0)
            {
                salt = new byte[SALTSIZE];
                new RNGCryptoServiceProvider().GetBytes(salt);
            }

            _salt = salt;
            _ver = ver;
            _keyMaterial = keyMaterial;
        }

        /// <summary>
        /// Builds the internal crypto classes based on the version#
        /// </summary>
        /// <exception cref="ArgumentException"></exception>
        public void GetVersionInfo()
        {
            switch (_ver)
            {
                case Version.VERSION_1:
                    _symCrypto = SymmetricAlgorithm.Create("DES");
                    _symCrypto.Mode = CipherMode.ECB;
                    _hMac = HMAC.Create("HMACMD5");
                    _iterationCount = 100;
                    _keyDerivation = new Rfc2898DeriveBytes(_keyMaterial, _salt, _iterationCount);
                    break;

                case Version.VERSION_2:
                    _symCrypto = SymmetricAlgorithm.Create("TripleDes");
                    _symCrypto.Mode = CipherMode.CBC;
                    _hMac = HMAC.Create("HMACSHA1");
                    _iterationCount = 1000;
                    _keyDerivation = new Rfc2898DeriveBytes(_keyMaterial, _salt, _iterationCount);
                    break;

                case Version.VERSION_3:
                    _symCrypto = SymmetricAlgorithm.Create("AesManaged");
                    _symCrypto.Mode = CipherMode.CBC;
                    _hMac = HMAC.Create("HMACSHA256");
                    _iterationCount = 4000;
                    _keyDerivation = new Rfc2898DeriveBytes(_keyMaterial, _salt, _iterationCount);
                    break;

                case Version.VERSION_4:
                    _symCrypto = SymmetricAlgorithm.Create("AesManaged");
                    _symCrypto.Mode = CipherMode.CBC;
                    _hMac = HMAC.Create("HMACSHA256");
                    _iterationCount = 20000;
                    _keyDerivation = new Rfc2898DeriveBytes(_keyMaterial, _salt, _iterationCount);
                    break;

                default:
                    throw new ArgumentException("Invalid crypto version.");

            }
        }

        /// <summary>
        /// Method to encrypt and MAC incoming plaintext
        /// </summary>
        /// <param name="plaintext"></param>
        /// <returns>Base64-encoded string that includes: version info, IV, salt, PBKDF# etc</returns>
        public string Protect(string plaintext)
        {
            byte[] plain = Encoding.UTF8.GetBytes(plaintext);
            var sb = new StringBuilder();

            // Encrypt the plaintext
            _symCrypto.GenerateIV();
            _symCrypto.Key = _keyDerivation.GetBytes(_symCrypto.KeySize >> 3);

            using (var enc = _symCrypto.CreateEncryptor())
            using (var memStream = new MemoryStream())
            using (var cryptoStream = new CryptoStream(memStream, enc, CryptoStreamMode.Write))
            {
                cryptoStream.Write(plain, 0, plain.Length);
                cryptoStream.FlushFinalBlock();

                sb.Append((int)_ver)
                    .Append(DELIM)
                    .Append(Convert.ToBase64String(_symCrypto.IV))
                    .Append(DELIM)
                    .Append(Convert.ToBase64String(_salt))
                    .Append(DELIM)
                    .Append(_iterationCount)
                    .Append(DELIM)
                    .Append(Convert.ToBase64String(memStream.ToArray()))
                    .Append(DELIM);

                memStream.Close();
                cryptoStream.Close();
            }

            // Now create an HMAC over all the previous data incl the ciphertext
            _hMac.Key = _keyDerivation.GetBytes(_hMac.HashSize);
            _hMac.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString()));
            sb.Append(Convert.ToBase64String(_hMac.Hash));

            return sb.ToString();
        }

        public string Unprotect(string protectedBlob)
        {
            if (string.IsNullOrWhiteSpace(protectedBlob))
                throw new ArgumentException($"'{nameof(protectedBlob)}' cannot be null or whitespace.", nameof(protectedBlob));

            var sb = new StringBuilder();

            // Pull out the parts of the protected blob
            // 0: version
            // 1: IV
            // 2: salt
            // 3: iteration count
            // 4: ciphertext
            string[] elements = protectedBlob.Split(new char[] { DELIM });

            // TODO: Everything

            return sb.ToString();
        }
    }

    static class Program
    {
        static void Main(string[] args)
        {
            byte[] pwd = { 0, 45, 33, 123, 45, 77, 66, 53, 32, 155, 43 };
            byte[] salt = { };

            string c1 = new AgileCrypto(pwd, salt, AgileCrypto.Version.VERSION_1).Protect("Hello!");
            string c2 = new AgileCrypto(pwd, salt, AgileCrypto.Version.VERSION_2).Protect("Hello!");
            string c3 = new AgileCrypto(pwd, salt, AgileCrypto.Version.VERSION_3).Protect("Hello!");
            string c4 = new AgileCrypto(pwd, salt, AgileCrypto.Version.VERSION_4).Protect("Hello!");
            string c5 = new AgileCrypto(pwd, salt, AgileCrypto.Version.VERSION_4).Protect("Hello!");

            string p1 = new AgileCrypto(pwd).Unprotect(c1);
        }
    }
}
