using Microsoft.AspNetCore.Mvc;
using MyDataSecurityApp.Services;

namespace MyDataSecurityApp.Controllers;

[ApiController]
[Route("[controller]/[action]")]
public class HomeController: Controller
{
    private readonly ISymmetricEncryptionService _symmetricEncryptionService;

    private readonly IAsymmetricEncryptionService _asymmetricEncryptionService;
    
    private readonly IHashingService _hashingService;
    
    public HomeController(
        ISymmetricEncryptionService symmetricEncryptionService,
        IAsymmetricEncryptionService asymmetricEncryptionService,
        IHashingService hashingService)
    {
        _symmetricEncryptionService = symmetricEncryptionService;
        _asymmetricEncryptionService = asymmetricEncryptionService;
        _hashingService = hashingService;
    }
    
    [HttpGet]
    public IActionResult Index()
    {
        return Ok("Hello, welcome to my app");
    }

    [HttpPost]
    public IActionResult SymmetricEncrypt(string text, string? secretKey = null, string? iv = null)
    {
        return Ok(_symmetricEncryptionService.Encrypt(text, secretKey, iv));
    }
    
    [HttpPost]
    public IActionResult SymmetricDecrypt(string cipherText, string? secretKey = null, string? iv = null)
    {
        return Ok(_symmetricEncryptionService.Decrypt(cipherText, secretKey, iv));
    }
    
    [HttpPost]
    public IActionResult AsymmetricEncrypt(string text, string? publicBase64Key = null)
    {
        return Ok(_asymmetricEncryptionService.Encrypt(text, publicBase64Key));
    }
    
    [HttpPost]
    public IActionResult AsymmetricDecrypt(string cipherText, string? privateBase64Key = null)
    {
        return Ok(_asymmetricEncryptionService.Decrypt(cipherText, privateBase64Key));
    }
    
    [HttpPost]
    public IActionResult Hash(string plainText, string? saltString = null, int? keySizeInBits = null, int? iterations = null)
    {
        var result = _hashingService.Hash(plainText, saltString, keySizeInBits, iterations);
        return Ok(new { hash = result.hash, salt = result.salt, keySizeInBits = result.keySizeInBits, iterations = result.iterations });
    }
    
    [HttpPost]
    public IActionResult Verify(string base64HashString, string rawString, string? saltString = null, int? keySizeInBits = null,
        int? iterations = null)
    {
        var result = _hashingService.Verify(base64HashString, rawString, saltString, keySizeInBits, iterations);
        return Ok(result);
    }
}