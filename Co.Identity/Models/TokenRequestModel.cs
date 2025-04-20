using System.ComponentModel.DataAnnotations;

namespace Co.Identity.Models;

public class TokenRequestModel
{
    [Required]
    public string? GrantType { get; set; }
    
    public string? UserName { get; set; }
    
    public string? Password { get; set; }
    
    public string? RefreshToken { get; set; }
    
    public string? ClientId { get; set; }
    
    public string? ClientSecret { get; set; }
    
    public string? Scope { get; set; }
} 