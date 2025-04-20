using System.ComponentModel.DataAnnotations;

namespace Co.Identity.Models;

public class RevokeTokenModel
{
    [Required]
    public string? RefreshToken { get; set; }
} 