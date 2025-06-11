using Microsoft.AspNetCore.Mvc;
using MyDataSecurityApp.Services;

namespace MyDataSecurityApp.Controllers;

[ApiController]
[Route("[controller]/[action]")]
public class HomeController: Controller
{
    public readonly ISymmetricEncryptionService _symmetricEncryptionService;
    
    public HomeController(ISymmetricEncryptionService symmetricEncryptionService)
    {
        _symmetricEncryptionService = symmetricEncryptionService;
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
}