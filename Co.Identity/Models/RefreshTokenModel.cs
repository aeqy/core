using System.ComponentModel.DataAnnotations;

namespace Co.Identity.Models;

public class RefreshTokenModel
{
    [Required]
    public string? RefreshToken { get; set; }
} 