using System;
using System.Text;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace PracticalAgileCrypto
{
    public class AgileCrypto
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
        private const char DELIM = '|';

        private Version             _ver;
        private SymmetricAlgorithm  _symCrypto;
        private HMAC                _hMac;
        private DeriveBytes         _keyDerivation;
        private int                 _iterationCount;
        private byte[]              _salt;
        private byte[]              _keyMaterial;
        private string              _cipherText;

        public string               CipherText { get { return _cipherText; } }

        public AgileCrypto(Version ver)
        {
            _ver = ver;
        }

        public AgileCrypto()
        {
            _ver = Version.VERSION_LATEST;
        }

        private void GetSalt()
        {
            // if the salt is non-existant, then create one
            if (_salt is null)
            {
                _salt = new byte[SALTSIZE];
                new RNGCryptoServiceProvider().GetBytes(_salt);
            }
        }

        /// <summary>
        /// Builds the internal crypto classes based on the version#
        /// </summary>
        /// <exception cref="ArgumentException"></exception>
        private void BuildCryptoObjects(string pwd)
        {
            _keyMaterial = Encoding.ASCII.GetBytes(pwd);

            switch (_ver)
            {
                case Version.VERSION_1:
                    _symCrypto = SymmetricAlgorithm.Create("DES");
                    _symCrypto.Mode = CipherMode.ECB;
                    _symCrypto.Padding = PaddingMode.PKCS7;
                    _hMac = null;
                    _iterationCount = 100;
                    _keyDerivation = new Rfc2898DeriveBytes(_keyMaterial, _salt, _iterationCount);
                    break;

                case Version.VERSION_2:
                    _symCrypto = SymmetricAlgorithm.Create("TripleDes");
                    _symCrypto.KeySize = 128;
                    _symCrypto.Mode = CipherMode.CBC;
                    _symCrypto.Padding = PaddingMode.PKCS7;
                    _hMac = HMAC.Create("HMACMD5");
                    _iterationCount = 1000;
                    _keyDerivation = new Rfc2898DeriveBytes(_keyMaterial, _salt, _iterationCount);
                    break;

                case Version.VERSION_3:
                    _symCrypto = SymmetricAlgorithm.Create("AesManaged");
                    _symCrypto.KeySize = 128;
                    _symCrypto.Mode = CipherMode.CBC;
                    _symCrypto.Padding = PaddingMode.PKCS7;
                    _hMac = HMAC.Create("HMACSHA1");
                    _iterationCount = 4000;
                    _keyDerivation = new Rfc2898DeriveBytes(_keyMaterial, _salt, _iterationCount);
                    break;

                case Version.VERSION_4:
                    _symCrypto = SymmetricAlgorithm.Create("AesManaged");
                    _symCrypto.KeySize = 256;
                    _symCrypto.Mode = CipherMode.CBC;
                    _symCrypto.Padding = PaddingMode.ANSIX923;
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
        /// <returns>Base64-encoded string that includes: version info, IV, PBKDF# etc</returns>
        public string Protect(string pwd, string plaintext)
        {
            GetSalt();
            BuildCryptoObjects(pwd);

            var sb = new StringBuilder();

            // Encrypt the plaintext
            _symCrypto.GenerateIV();
            _symCrypto.Key = _keyDerivation.GetBytes(_symCrypto.KeySize >> 3);

            // Create an encryptor to perform the stream transform.
            ICryptoTransform encryptor = _symCrypto.CreateEncryptor();

            // Create the streams used for encryption.
            byte[] encrypted;
            using (MemoryStream msEncrypt = new MemoryStream())
            using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            {
                using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                {
                    swEncrypt.Write(plaintext);
                }
                encrypted = msEncrypt.ToArray();
            }

            _cipherText = Convert.ToBase64String(encrypted);

            sb.Append((int)_ver)
                .Append(DELIM)
                .Append(Convert.ToBase64String(_symCrypto.IV))
                .Append(DELIM)
                .Append(Convert.ToBase64String(_salt))
                .Append(DELIM)
                .Append(_iterationCount)
                .Append(DELIM)
                .Append(Convert.ToBase64String(encrypted))
                .Append(DELIM);

            // Now create an HMAC over all the previous data
            // incl the version#, IV, salt, iteration count and ciphertext
            // all but the ciphertext are plaintext, we're just protecting
            // them all from tampering

            if (_hMac != null)
            {
                // Derive a new key for this work
                _hMac.Key = _keyDerivation.GetBytes(_hMac.HashSize);
                _hMac.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString()));
                sb.Append(Convert.ToBase64String(_hMac.Hash));
            } 
            else
            {
                sb.Append("");
            }

            return sb.ToString();
        }

        /// <summary>
        /// Method to verify the MAC and the decrypt a protected blob
        /// </summary>
        /// <param name="pwd"></param>
        /// <param name="protectedBlob"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public string Unprotect(string pwd, string protectedBlob)
        {
            if (string.IsNullOrWhiteSpace(protectedBlob))
                throw new ArgumentException($"'{nameof(protectedBlob)}' cannot be null or whitespace.", nameof(protectedBlob));

            // Pull out the parts of the protected blob
            // 0: version
            // 1: IV
            // 2: salt
            // 3: iteration count
            // 4: ciphertext
            string[] elements = protectedBlob.Split(new char[] { DELIM });

            // get version
            int.TryParse(elements[0], out int ver);
            _ver = (Version)ver;

            // get IV
            byte[] iv = System.Convert.FromBase64String(elements[1]);

            // get salt
            _salt = System.Convert.FromBase64String(elements[2]);

            // get iteration count
            int.TryParse(elements[3], out int iter);
            _iterationCount = iter;

            // get ciphertext
            byte[] ciphertext = System.Convert.FromBase64String(elements[4]);

            BuildCryptoObjects(pwd);

            _symCrypto.Key = _keyDerivation.GetBytes(_symCrypto.KeySize >> 3);
            _symCrypto.IV = iv;

            string plaintext;
            ICryptoTransform decryptor = _symCrypto.CreateDecryptor();
            using (MemoryStream msDecrypt = new MemoryStream(ciphertext))
            using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
            using (StreamReader srDecrypt = new StreamReader(csDecrypt))
            {
                plaintext = srDecrypt.ReadToEnd();
            }

            return plaintext;
        }
    }

    static class Program
    {
        static void Main(string[] args)
        {
            string pwd = "SSsshh!!";
            string plaintext = "Hello, World!";

            string c1 = new AgileCrypto(AgileCrypto.Version.VERSION_1).Protect(pwd, plaintext);
            string p1 = new AgileCrypto().Unprotect(pwd, c1);
            Console.WriteLine($"P1 {p1 == plaintext}");

            string c2 = new AgileCrypto(AgileCrypto.Version.VERSION_2).Protect(pwd, plaintext);
            string p2 = new AgileCrypto().Unprotect(pwd, c2);
            Console.WriteLine($"P2 {p2 == plaintext}");

            string c3 = new AgileCrypto(AgileCrypto.Version.VERSION_3).Protect(pwd, plaintext);
            string p3 = new AgileCrypto().Unprotect(pwd, c3);
            Console.WriteLine($"P3 {p3 == plaintext}");

            string c4 = new AgileCrypto(AgileCrypto.Version.VERSION_4).Protect(pwd, plaintext);
            string p4 = new AgileCrypto().Unprotect(pwd, c4);
            Console.WriteLine($"P4 {p4 == plaintext}");

            string c5 = new AgileCrypto(AgileCrypto.Version.VERSION_4).Protect(pwd, plaintext);
            string p5 = new AgileCrypto().Unprotect(pwd, c5);
            Console.WriteLine($"P5 {p5 == plaintext}");

            // two plaintexts with the same key should yield two different ciphertexts
            // because the IV and salt are always different
            Console.WriteLine($"C4 != c5 {c4 != c5}");
        }
    }
}
