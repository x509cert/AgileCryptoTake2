using System;
using System.Text;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace PracticalAgileCrypto
{
    class AgileCrypto
    {
        // salte size is byte count, not bit count
        private const int SALTSIZE = 128 / 8;
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
        private CipherMode          _blockMode;
        private Version             _ver;
        private byte[]              _salt;

        public AgileCrypto(byte[] keyMaterial,
                           byte[] salt,
                           Version ver = Version.VERSION_LATEST)
        {
            // if the salt is non-existant, then create one
            if (salt.Length == 0)
            {
                salt = new byte[SALTSIZE];
                new System.Security.Cryptography.RNGCryptoServiceProvider().GetBytes(salt);
            }

            _salt = salt;
            _ver = ver;

            switch (ver)
            {
                case Version.VERSION_1:
                    _symCrypto = SymmetricAlgorithm.Create("DES");
                    _hMac = HMAC.Create("HMACMD5");
                    _iterationCount = 0;
                    _keyDerivation = null;
                    _blockMode = CipherMode.ECB;
                    break;

                case Version.VERSION_2:
                    _symCrypto = SymmetricAlgorithm.Create("TripleDes");
                    _hMac = HMAC.Create("HMACSHA1");
                    _iterationCount = 1000;
                    _keyDerivation = new Rfc2898DeriveBytes(keyMaterial, _salt, _iterationCount);
                    _blockMode = CipherMode.CBC;
                    break;

                case Version.VERSION_3:
                    _symCrypto = SymmetricAlgorithm.Create("AesManaged");
                    _hMac = HMAC.Create("HMACSHA256");
                    _iterationCount = 4000;
                    _keyDerivation = new Rfc2898DeriveBytes(keyMaterial, _salt, _iterationCount);
                    _blockMode = CipherMode.CBC;
                    break;

                case Version.VERSION_4:
                    _symCrypto = SymmetricAlgorithm.Create("AesManaged");
                    _hMac = HMAC.Create("HMACSHA256");
                    _iterationCount = 20000;
                    _keyDerivation = new Rfc2898DeriveBytes(keyMaterial, _salt, _iterationCount);
                    _blockMode = CipherMode.CBC;
                    break;

                default:
                    throw new ArgumentException("Wrong crypto version.");
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
            {
                using (var memStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memStream, enc, CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(plain, 0, plain.Length);
                        cryptoStream.FlushFinalBlock();

                        sb.Append((int)_ver);
                        sb.Append(DELIM);
                        sb.Append(Convert.ToBase64String(_symCrypto.IV));
                        sb.Append(DELIM);
                        sb.Append(Convert.ToBase64String(_salt));
                        sb.Append(DELIM);
                        sb.Append(_iterationCount);
                        sb.Append(DELIM);
                        sb.Append(Convert.ToBase64String(memStream.ToArray()));
                        sb.Append(DELIM);

                        memStream.Close();
                        cryptoStream.Close();
                    }
                }
            }

            // Now create an HMAC over all the previous data incl the ciphertext
            using (var hmac = _hMac)
            {
                _hMac.Key = _keyDerivation.GetBytes(_hMac.HashSize);
                _hMac.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString()));
                sb.Append(Convert.ToBase64String(_hMac.Hash));
            }

            return sb.ToString();
        }

        public string Unprotect()
        {
            var sb = new StringBuilder();

            // TODO: Everything

            return sb.ToString();
        }
    }
    class Program
    {
        static void Main(string[] args)
        {
            byte[] pwd = { 0, 45, 33, 123, 45, 77, 66, 53, 32, 155, 43 };
            byte[] salt = { };

            string s1 = new AgileCrypto(pwd, salt, AgileCrypto.Version.VERSION_3).Protect("Hello!");
            string s2 = new AgileCrypto(pwd, salt, AgileCrypto.Version.VERSION_3).Protect("Hello!");
            string s3 = new AgileCrypto(pwd, salt, AgileCrypto.Version.VERSION_3).Protect("Hello!");
            string s4 = new AgileCrypto(pwd, salt, AgileCrypto.Version.VERSION_3).Protect("Hello!");
        }
    }
}
