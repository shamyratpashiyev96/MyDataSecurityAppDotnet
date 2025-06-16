using System.Security.Cryptography;
using System.Text;

namespace MyDataSecurityApp.Services;

public interface IAsymmetricEncryptionService
{
    /// <summary>
    /// The process of encryption consists of these steps below:
    /// 1) Breaking base64 encoded public key into bytes of normal text (normal utf8 string which is encrypted)
    /// 2) Importing public key which is in byte[] format, into RSA object instance
    /// 3) Breaking a plain text that needs to be encrypted into byte[]
    /// 4) Then encrypting that byte[] of plain text (passing default padding)
    /// 5) Returning the encrypted byte[] converting it into base64 string
    /// </summary>
    string Encrypt(string plainText, string? base64PublicKey = null);

    /// <summary>
    /// The process of decryption consists of these steps below:
    /// 1) Breaking base64 encoded private key into bytes of normal text (normal utf8 string which is encrypted)
    /// 2) Importing public key which is in byte[] format, into RSA object instance
    /// 3) Breaking base64 encoded cipher text into bytes of normal text (normal utf8 string which is encrypted)
    /// 4) Then decrypting that byte[] of cipher text (passing default padding)
    /// 5) Assembling decrypted byte[] back as a normal string (which is original text)
    /// 6) Returning the result
    /// </summary>
    string Decrypt(string cipherText, string? base64PrivateKey = null);
}

public class AsymmetricEncryptionService : IAsymmetricEncryptionService
{
    private const int DefaultKeySizeInBits = 4096;
    
    private static RSAEncryptionPadding DefaultEncryptionPadding = RSAEncryptionPadding.OaepSHA256;
    
    // 4096 bit public key
    private const string DefaultPublicBase64Key =
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6tv+4irmKBLTNYlh2vDg\nQmfQqQbBcEnGSF4IRNDCeSjKqSyJmmL2ZUpdpLRwXJj5/cPypKcm670W1uQBv5vh\noziqKb7bhCO+Dn6SlV9DUbMyMygz5axBBuT6X8b8wAw7dZifKdJfl4fkBdp/jRrs\nFIsmG2xmMR/fSwhrgmbeeeqRAvHg5yJqFdGQxNZeFfeTSVkMcRHqkor1m9CT5kEQ\nvAUsy6ddgkxsfaAmT0qEBqpVGvQeAu5L78NRquUIxPPerTnc5g3kpEAddU5ezxxc\nIDbvybutOgStQX6xeF5PamSpYbTfFsIfT6Po7ZuYy8B9HGKyOk1GQ/ExaXcZtC/a\nPQIDAQAB";
    
    // 4096 bit public key
    private const string DefaultPrivateBase64Key = 
        "MIIEpAIBAAKCAQEA6tv+4irmKBLTNYlh2vDgQmfQqQbBcEnGSF4IRNDCeSjKqSyJ\nmmL2ZUpdpLRwXJj5/cPypKcm670W1uQBv5vhoziqKb7bhCO+Dn6SlV9DUbMyMygz\n5axBBuT6X8b8wAw7dZifKdJfl4fkBdp/jRrsFIsmG2xmMR/fSwhrgmbeeeqRAvHg\n5yJqFdGQxNZeFfeTSVkMcRHqkor1m9CT5kEQvAUsy6ddgkxsfaAmT0qEBqpVGvQe\nAu5L78NRquUIxPPerTnc5g3kpEAddU5ezxxcIDbvybutOgStQX6xeF5PamSpYbTf\nFsIfT6Po7ZuYy8B9HGKyOk1GQ/ExaXcZtC/aPQIDAQABAoIBADweZHhwksnfR8GE\nkVACKOXWvUsHN60OtXsA1w0Gg0GQd5AmnnKusnPrPV1T8w9A+X1EE3CieQwPMzF+\n3BO4S2IEt0pIWNjSbWw4aj1iTVE0lb0SpXY9ScgCBTVPMpPWjcHkd5m1CFM5rdzx\nuYTdR2Fa3T5X2TDp/7atSRfwTTLXow1KoqfnqzdXrn/GZsex+Plo18EKX9G2HNlb\nbJyCuTNXJapyLF9rs8FziSelHC0OtithZVceQMYQIheyczKNHtDgU2IKMqLfxF8Z\nih5zLLWRXRPQhc0DywflvTrNvv1EDIAeIsrNDD77aVWZPZ4VHbAYX6U2QzfUkcn2\nj3C1+QECgYEA9zeGTKNkNYxdKd/TyfjKawKws9KD0NnNxdUgZjXK5edNy0zWgymp\nDrB80camHrme8gWARRmbi9dqE8rM6jqa8hzMuVhc5OLkPyxKRKQxNxwKZTVLnVDY\np9LJC1GLMtmIOGOdHFDBR41kAP6mM3k02l1NMDJvhDRct7UDH2pnCGkCgYEA8zQT\nzhdkjS52JNuoQxUbkVWlRsRd/Ph+8r6gdhVPIwwijQ2moa1cJVJ1kmEdcJ8JoPIt\npAsVlyH6oMMXljlILam1tgMrIQFp6z4uz7MT/i8NnWxPcT7Y4nYlB3DCXABF5Ayz\nu8z22MvG67PVPWmy4z8stPl+Kdt0lom4UhMCqLUCgYEAqOkNH8v7qgKvnO7LnBIa\n66a46QSK/+XxDJykOHHEofS6WI+1eYS7d8fqYMJjulaFXUOY8p2eg5u5ZLCJ9ff4\n6jf3QSQ4xEKqROeUDvZIkijciW4yrdgRUAlbSBp9C09KHY0iSbh7dtIKZAuZr02/\naPuaw7WSMDg+qV5KNerTXxECgYAtAKL1jNCXa1SDR34gQ6ShRQbbTHTT3auoAWwx\nzYmiQ5mVHkSKQEj/wv1sg7nt4A/pD0cwxrhNCgWVf+Q6cQkRIgk0z+tIJTnTRONm\nnY2CiHRtf+BHZUi+xvvdH5lnasmEBHGxu6Clxzdc4B8CSS/H6yW7qzsURb6SKJPJ\n5CimzQKBgQDdSvoUfFnzIF6iTvPATIinE+NXNsEX2hghqvg0VOg4Sz/fsoCv6sbn\n+LdmR4eMGX+jHmIAB+BbOhjBvhIvgu0Cyt6SsUp6RDOk/xpOhqXEtWR/Ncyi/zPQ\n8QEV3o3YuWIumxrRl8WWxzpXEgsBhgi92EcrQE3qs/Rk90MVN9+dmg==";

    public string Encrypt(string plainText, string? base64PublicKey = null)
    {
        if (base64PublicKey == null)
        {
            base64PublicKey = DefaultPublicBase64Key;
        }

        using var rsa = RSA.Create(DefaultKeySizeInBits);
        {
            var publicKeyBytes = Convert.FromBase64String(base64PublicKey);
            
            // If your key is in PKCS#8 format (keys are mostly in this format).
            rsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);
            
            // If your key is in PKCS#1 format
            // rsa.ImportRSAPublicKey(publicKeyBytes, out _);

            var buffer = Encoding.UTF8.GetBytes(plainText);
            var encryptedBuffer = rsa.Encrypt(buffer, DefaultEncryptionPadding);
            return Convert.ToBase64String(encryptedBuffer);
        }
    }

    public string Decrypt(string cipherText, string? base64PrivateKey = null)
    {
        if (base64PrivateKey == null)
        {
            base64PrivateKey = DefaultPrivateBase64Key;
        }

        using var rsa = RSA.Create(DefaultKeySizeInBits);
        {
            var publicKeyBytes = Convert.FromBase64String(base64PrivateKey);
            rsa.ImportRSAPrivateKey(publicKeyBytes, out _);
            var buffer = Convert.FromBase64String(cipherText);
            var decryptedBuffer = rsa.Decrypt(buffer, DefaultEncryptionPadding);
            return Encoding.UTF8.GetString(decryptedBuffer);
        }
    }
}