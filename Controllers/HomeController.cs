using Microsoft.AspNetCore.Mvc;
using MyDataSecurityApp.Services;

namespace MyDataSecurityApp.Controllers;

[ApiController]
[Route("[controller]/[action]")]
public class HomeController: Controller
{
    private readonly ISymmetricEncryptionService _symmetricEncryptionService;

    private readonly IAsymmetricEncryptionService _asymmetricEncryptionService;
    
    public HomeController(
        ISymmetricEncryptionService symmetricEncryptionService,
        IAsymmetricEncryptionService asymmetricEncryptionService)
    {
        _symmetricEncryptionService = symmetricEncryptionService;
        _asymmetricEncryptionService = asymmetricEncryptionService;
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
}