using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Encryption
{
    public class EncryptionClass
    {
        public static string FormatCipher(string prefix,
                                          string cipher,
                                          string salt,
                                          int saltIndexPosition)
        {
            string saltPart1 = salt.Substring(0, 10);
            string saltPart2 = salt.Substring(10);


            StringBuilder cipherStringBuilder = new StringBuilder();
            cipherStringBuilder.Append(prefix);


            StringBuilder cipherBodyStringBuilder = new StringBuilder();
            cipherBodyStringBuilder.Append(cipher);
            cipherBodyStringBuilder.Insert(saltIndexPosition, saltPart1);
            cipherBodyStringBuilder.Insert(saltPart1.Length + 1 + saltIndexPosition, saltPart2);

            cipherStringBuilder.Append(cipherBodyStringBuilder);

            string cipherString = cipherStringBuilder.ToString();

            return cipherString;
        }

        public static string GenerateRandomSALT
        {
            get
            {
                StringBuilder builder = new StringBuilder();
                builder.Append(RandomString(5, true));
                builder.Append(RandomNumber(100000, 999999));
                builder.Append(RandomString(5, false));
                return builder.ToString();
            }
        }

        public static string GenerateExcludeCharacters
        {
            get
            {
                StringBuilder builder = new StringBuilder();
                builder.Append(RandomString(1, false));
                builder.Append(RandomNumber(0, 9));
                builder.Append(RandomString(1, true));
                return builder.ToString();
            }
        }

        public static string RefineTheSALT(string SALT,
                                           string excludedText)
        {
            StringBuilder saltToBeRefined = new StringBuilder();
            saltToBeRefined.Append(SALT);
            StringBuilder excludedTextArray = new StringBuilder(excludedText);

            for (int i = 0; i < excludedTextArray.Length; i++)
            {
                saltToBeRefined.Replace(excludedTextArray[i].ToString(), "");
            }

            return saltToBeRefined.ToString();
        }

        public static string GeneratePossitionString
        {
            get
            {
                StringBuilder builder = new StringBuilder();
                builder.Append(RandomString(1, false));
                builder.Append(RandomString(1, true));
                return builder.ToString();
            }
        }

        public static int CalculateInsertPossition(string positionString)
        {
            int position = 0;
            char[] charArray = positionString.ToArray();
            foreach (var letter in charArray)
            {
                int charValue = System.Convert.ToInt32(letter);
                position = position + charValue;
            }
            return position % 3;
        }

        // Generate the random string with a given size and case.   
        // If the second parameter is true, the return string is lowercase  

        private static string RandomString(int size, bool lowerCase)
        {
            StringBuilder builder = new StringBuilder();
            Random random = new Random();
            char ch;
            for (int i = 0; i < size; i++)
            {
                ch = Convert.ToChar(Convert.ToInt32(Math.Floor(26 * random.NextDouble() + 65)));
                builder.Append(ch);
            }
            if (lowerCase)
                return builder.ToString().ToLower();
            return builder.ToString();
        }

        // Generate a random number between two numbers    
        private static int RandomNumber(int min,
                                        int max)
        {
            Random random = new Random();
            return random.Next(min, max);
        }

        public async Task<string> EncryptAndEncode(string raw,
                                                   string IV,
                                                   string PASSWORD)
        {

            //generate the position string 
            string positionString = GeneratePossitionString;


            //calculate the position
            int positionToInsert = CalculateInsertPossition(positionString);

            //generate Full SALT of 16Char
            string salt = GenerateRandomSALT;

            //generate the exclude char
            string excludeText = GenerateExcludeCharacters;

            //filter the SALT with the above
            string refinedSALT = RefineTheSALT(salt, excludeText);


            string encrypted = await EncryptTheText(raw, IV, PASSWORD, refinedSALT);
            

            return FormatCipher(positionString + excludeText, encrypted, salt, positionToInsert);
        }

        private Task<string> EncryptTheText(string raw,
                                            string IV,
                                            string PASSWORD,
                                            string refinedSALT)
        {
            string encrypted = "";
            using (var csp = new AesCryptoServiceProvider())
            {
                ICryptoTransform e = GetCryptoTransform(csp, true, IV, PASSWORD, refinedSALT);
                byte[] inputBuffer = Encoding.UTF8.GetBytes(raw);
                byte[] output = e.TransformFinalBlock(inputBuffer, 0, inputBuffer.Length);
                encrypted = Convert.ToBase64String(output);

            }

            return Task.FromResult(encrypted);
        }


        public bool IsDashboard(string cipher)
        {
            bool isDashboard = cipher.Contains("%");
            return isDashboard;
        }


        //public static string DecodeAndDecrypt(string encrypted, string IV, string PASSWORD, string SALT)
        public async Task<string> DecodeAndDecrypt(string encrypted,
                                                   string IV,
                                                   string Key)
        {
            try
            {
                //check for dashboard to apply different algorithm
                bool isDashBoard = IsDashboard(encrypted);
                encrypted = encrypted.Replace("%", "");
                //Cipher PART 1 for Position string & Removel text for the SALT
                var positionString = encrypted.Substring(0, 2);
                var positionToInsert = CalculateInsertPossition(positionString);
                var removalString = encrypted.Substring(2, 3);

                var cipherPart2 = encrypted.Substring(5, encrypted.Length - 5);
                var saltPart1 = cipherPart2.Substring(positionToInsert, 10);
                var saltPart2 = cipherPart2.Substring(positionToInsert + saltPart1.Length + 1, 6);
                var salt = saltPart1 + saltPart2;

                StringBuilder refinedCipher = new StringBuilder(cipherPart2);
                refinedCipher.Replace(saltPart1, "");
                refinedCipher.Replace(saltPart2, "");
                var refinedSalt = RefineTheSALT(salt, removalString);
                string refinedCipherStr = refinedCipher.ToString();

                if (isDashBoard)
                    return await DecryptAESString(refinedCipherStr, Key, IV);
                else
                    return await DecryptThetext(refinedSalt, refinedCipher, Key, IV);

            }
            catch (Exception)
            {
                return "Unauthorized Access";
            }

        }

        private Task<string> DecryptThetext(string refinedSalt,
                                            StringBuilder refinedCipher,
                                            string Key,
                                            string IV)
        {
            using (var csp = new AesCryptoServiceProvider())
            {
                var d = GetCryptoTransform(csp, false, IV, Key, refinedSalt);
                byte[] output = Convert.FromBase64String(refinedCipher.ToString());
                byte[] decryptedOutput = d.TransformFinalBlock(output, 0, output.Length);
                string decypted = Encoding.UTF8.GetString(decryptedOutput);
                return Task.FromResult(decypted);
            }
        }


        private static ICryptoTransform GetCryptoTransform(AesCryptoServiceProvider csp,
                                                           bool encrypting,
                                                           string IV,
                                                           string PASSWORD,
                                                           string SALT)
        {
            csp.Mode = CipherMode.CBC;
            csp.Padding = PaddingMode.PKCS7;
            var spec = new Rfc2898DeriveBytes(Encoding.UTF8.GetBytes(PASSWORD), Encoding.UTF8.GetBytes(SALT), 65536);
            byte[] key = spec.GetBytes(16);


            csp.IV = Encoding.UTF8.GetBytes(IV);
            csp.Key = key;
            if (encrypting)
            {
                return csp.CreateEncryptor();
            }
            return csp.CreateDecryptor();
        }

        //Decrypt for ReactJS Web 
        public static async Task<string> DecryptAESString(string cipherText, string key, string IVKey)
        {
            var keybytes = System.Text.Encoding.UTF8.GetBytes(key);
            var iv = Encoding.UTF8.GetBytes(IVKey);

            var encrypted = Convert.FromBase64String(cipherText);
            var decriptedFromJavascript = await DecryptStringFromBytes(encrypted, keybytes, iv);
            return string.Format(decriptedFromJavascript);
        }


        private static Task<string> DecryptStringFromBytes(byte[] cipherText, byte[] key, byte[] iv)
        {
            // Check arguments.  
            if (cipherText == null || cipherText.Length <= 0)
            {
                throw new ArgumentNullException("cipherText");
            }
            if (key == null || key.Length <= 0)
            {
                throw new ArgumentNullException("key");
            }
            if (iv == null || iv.Length <= 0)
            {
                throw new ArgumentNullException("key");
            }

            // Declare the string used to hold  
            // the decrypted text.  
            string plaintext = null;

            // Create an RijndaelManaged object  
            // with the specified key and IV.  
            using (var rijAlg = new RijndaelManaged())
            {
                //Settings  
                rijAlg.Mode = CipherMode.CBC;
                rijAlg.Padding = PaddingMode.PKCS7;
                rijAlg.FeedbackSize = 128;

                rijAlg.Key = key;
                rijAlg.IV = iv;

                // Create a decrytor to perform the stream transform.  
                var decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                try
                {
                    // Create the streams used for decryption.  
                    using (var msDecrypt = new System.IO.MemoryStream(cipherText))
                    {
                        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {

                            using (var srDecrypt = new System.IO.StreamReader(csDecrypt))
                            {
                                // Read the decrypted bytes from the decrypting stream  
                                // and place them in a string.  
                                plaintext = srDecrypt.ReadToEnd();

                            }

                        }
                    }
                }
                catch
                {
                    plaintext = "keyError";
                }
            }

            return Task.FromResult(plaintext);
        }




    }
}
