using System.ComponentModel.DataAnnotations;

namespace Co.Identity.Models;

public class RegisterModel
{
    [Required]
    [EmailAddress]
    public string? Email { get; set; }
    
    [Required]
    [StringLength(100, MinimumLength = 6)]
    public string? Password { get; set; }
    
    [Required]
    [Compare("Password")]
    public string? ConfirmPassword { get; set; }
    
    public string? FirstName { get; set; }
    
    public string? LastName { get; set; }
    
    public string? PhoneNumber { get; set; }
} 