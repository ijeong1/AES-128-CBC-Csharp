using System.Security.Cryptography;
using System.Text;
using System;

namespace AESEncrtyptor
{
    public class CSIdentityAPICrypto
    {
        public const int AES_KEY_SIZE = 16;
        private MD5 _AESKeyHashingAlgorithm;
        private Rijndael _AESCryptoAlogrithm;
        private byte[] _AESKey;

        public CSIdentityAPICrypto(string aesPassword)
        {
            AESPassword = aesPassword;
        }

        public string AESPassword { get; protected set; }

        protected MD5 AESKeyHashingAlgorithm
        {
            get
            {
                if (_AESKeyHashingAlgorithm == null)
                    _AESKeyHashingAlgorithm = MD5.Create();

                return _AESKeyHashingAlgorithm;
            }
        }

        protected Rijndael AESCryptoAlgorithm
        {
            get
            {
                if (_AESCryptoAlogrithm == null)
                {
                    _AESCryptoAlogrithm = Rijndael.Create();
                    _AESCryptoAlogrithm.BlockSize = 128;
                    _AESCryptoAlogrithm.Mode = CipherMode.CBC;
                    _AESCryptoAlogrithm.Padding = PaddingMode.Zeros;
                }

                return _AESCryptoAlogrithm;
            }
        }

        protected byte[] AESKey
        {
            get
            {
                if (_AESKey == null)
                {
                    byte[] keyHash = AESKeyHashingAlgorithm.ComputeHash(Encoding.ASCII.GetBytes(AESPassword));
                    string keyHashText = HexEncode(keyHash);
                    _AESKey = Encoding.ASCII.GetBytes(keyHashText.Substring(0, AES_KEY_SIZE));
                }

                return _AESKey;
            }
        }

        public static string HexEncode(byte[] data)
        {
            StringBuilder buff = new StringBuilder(data.Length * 2);
            foreach (byte b in data) buff.Append(b.ToString("x2"));
            return buff.ToString();
        }

        public static byte[] HexDecode(string hex)
        {
            int len = hex.Length;
            byte[] bytes = new byte[len / 2];
            for (int i = 0; i < len; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        public string AESEncrypt(string clearText)
        {
            AESCryptoAlgorithm.GenerateIV();
            byte[] iv = AESCryptoAlgorithm.IV;
            int ivSize = iv.Length;
            ICryptoTransform encryptor = AESCryptoAlgorithm.CreateEncryptor(AESKey, iv); int blockSize = encryptor.InputBlockSize;
            byte[] clearBytes = Encoding.ASCII.GetBytes(clearText);
            byte[] cryptBytes = encryptor.TransformFinalBlock(clearBytes, 0, clearBytes.Length);
            int cryptSize = cryptBytes.Length;
            // Combine the IV and the encrypted data
            byte[] totalBytes = new byte[ivSize + cryptSize]; Array.Copy(iv, 0, totalBytes, 0, ivSize); Array.Copy(cryptBytes, 0, totalBytes, ivSize, cryptSize);
            // Lastly, Base64 encode the whole thing
            return Convert.ToBase64String(totalBytes);
        }

        public string URLEncodeAESEncryption(string clearText)
        {
            return AESEncrypt(clearText);
        }

        public string URLDecodeAESEncryption(string clearText)
        {
            return AESDecrypt(clearText);
        }

        public string AESDecrypt(string cryptText)
        {
            // Seed and construct the transformation used for decrypting AESCryptoAlgorithm.GenerateIV();
            AESCryptoAlgorithm.GenerateIV();
            byte[] iv = AESCryptoAlgorithm.IV;
            int ivSize = iv.Length;
            ICryptoTransform decryptor = AESCryptoAlgorithm.CreateDecryptor(AESKey, iv);

            // The crypt text is expected to be encoded in base64 format, decode it... byte[] cryptBytes = Convert.FromBase64String(cryptText);
            byte[] cryptBytes = Convert.FromBase64String(cryptText);
            byte[] clearBytes = decryptor.TransformFinalBlock(cryptBytes, 0, cryptBytes.Length);

            return Encoding.ASCII.GetString(clearBytes, ivSize, clearBytes.Length - ivSize).TrimEnd('\0');
        }
    }
}
