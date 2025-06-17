using System.Security.Cryptography;
using System.Text;

namespace MyDataSecurityApp.Services;

public interface IHashingService
{
    /// <summary>
    /// The process of hashing consists of these steps below:
    /// 1) Breaking the salt string into bytes.
    /// 2) Creating new Rfc2898DeriveBytes() obj passing all the necessary parameters for hashing as a constructor arguments
    ///    and it generates hash in bytes.
    /// 3) Returning the hashed result converting into base64 encoding, along with other hashing parameters
    ///    which will be used later for verification
    /// </summary>
    (string hash, string salt, int keySizeInBits, int iterations) Hash(string plainText, string? saltString = null, int? keySizeInBits = null, int? iterations = null);

    /// <summary>
    /// The way verification works is really simple, you just get base64HashString and the raw version of that hash
    /// and then just hashing that rawString and comparing the result with already provided base64HashString
    /// because if all the parameters provided are correct, it should generate the same hash
    /// </summary>
    bool Verify(string base64HashString, string rawString, string? saltString = null, int? keySizeInBits = null,
        int? iterations = null);
}

public class HashingService : IHashingService
{
    private const string SaltString = "ee190ebaf2ac4ac8976484f1bce4addb";
    private int KeySizeInBytes = 512 / 8;
    private const int Iterations = 4096;

    public (string hash, string salt, int keySizeInBits, int iterations) Hash(string plainText, string? saltString = null, int? keySizeInBits = null, int? iterations = null)
    {
        if (saltString == null)
        {
            saltString = SaltString;
        }

        if (keySizeInBits != null)
        {
            KeySizeInBytes = keySizeInBits.Value / 8;
        }

        if (iterations == null)
        {
            iterations = Iterations;
        }

        var saltStringBytes = Encoding.UTF8.GetBytes(saltString);
        using var pbkdf2 = new Rfc2898DeriveBytes(plainText, saltStringBytes, iterations.Value, HashAlgorithmName.SHA512);
        {
            // Getting hashed bytes, passing the key length in bytes
            var hashedResult = pbkdf2.GetBytes(KeySizeInBytes);
            return (Convert.ToBase64String(hashedResult), saltString, keySizeInBits.Value, iterations.Value);
        }
    }

    public bool Verify(string base64HashString, string rawString, string? saltString = null, int? keySizeInBits = null,
        int? iterations = null)
    {
        var hashResult = Hash(rawString, saltString, keySizeInBits, iterations);
        
        return hashResult.hash == base64HashString;
    }
}