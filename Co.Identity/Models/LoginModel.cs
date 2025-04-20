using System.ComponentModel.DataAnnotations;

namespace Co.Identity.Models;

public class LoginModel
{
    [Required]
    public string? Username { get; set; }
    
    [Required]
    public string? Password { get; set; }
} 