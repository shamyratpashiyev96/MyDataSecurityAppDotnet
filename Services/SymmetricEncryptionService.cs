using System.Security.Cryptography;
using System.Text;

namespace MyDataSecurityApp.Services;

public interface ISymmetricEncryptionService
{
    /// <summary>
    /// The process of encryption consists of these steps below:
    /// 1) Breaking a rawString into byte[]
    /// 2) Running those bytes through encryption stream
    /// 3) Assembling byte[] back converting it to base64 string
    /// 4) Returning the result (base64 string)
    /// </summary>
    string Encrypt(string rawText, string? secretKey = null, string? iv = null);

    /// <summary>
    /// The process of decryption consists of these steps below:
    /// 1) Breaking base64 encoded cipher text into bytes of normal text (normal utf8 string which is encrypted)
    /// 2) Running it through decryption stream
    /// 3) Assembling decrypted byte[] back as a normal string (which is original text)
    /// 4) Returning the result
    /// </summary>
    string Decrypt(string cipherText, string? secretKey = null, string? iv = null);
}

public class SymmetricEncryptionService : ISymmetricEncryptionService
{
    // Base64 key with 256-bit length
    private const string Default256BitKey = "Ove54m2RfMVF0yJviB7atJmLdMpsVd0TfwKvOWDEmuY=";

    // Base64 iv with 128-bit length (usually AES requires 128-bit iv even for 256-bit key)
    private const string Default128BitIv = "bhPSkEeJrD8Re2UofOCTrQ==";

    public string Encrypt(string rawText, string? secretKey = null, string? iv = null)
    {
        if (secretKey == null)
        {
            secretKey = Default256BitKey;
        }
    
        if (iv == null)
        {
            iv = Default128BitIv;
        }
    
        var rawTextBytes = Encoding.UTF8.GetBytes(rawText);
        
        using var aes = Aes.Create();
        {
            aes.Key = Convert.FromBase64String(secretKey);
            aes.IV = Convert.FromBase64String(iv);
    
            using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            {
                using var memoryStream = new MemoryStream();
                {
                    using var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
                    {
                        cryptoStream.Write(rawTextBytes);
                        cryptoStream.FlushFinalBlock();
                        
                        var resultBytes = memoryStream.ToArray();
                        return Convert.ToBase64String(resultBytes);
                    }
                }
            }
        }
    }

public string Decrypt(string cipherText, string? secretKey = null, string? iv = null)
    {
        if (secretKey == null)
        {
            secretKey = Default256BitKey;
        }

        if (iv == null)
        {
            iv = Default128BitIv;
        }

        var buffer = Convert.FromBase64String(cipherText);
        
        using var aes = Aes.Create();
        {
            aes.Key = Convert.FromBase64String(secretKey);
            aes.IV = Convert.FromBase64String(iv);
        
            using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            {
                using var memoryStream = new MemoryStream();
                {
                    using var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write);
                    {
                        cryptoStream.Write(buffer);
                        cryptoStream.FlushFinalBlock();

                        var resultBytes = memoryStream.ToArray();
                        
                        return Encoding.UTF8.GetString(resultBytes);
                    }
                }
            }
        }
    }
}