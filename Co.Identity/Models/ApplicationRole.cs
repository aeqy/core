using Microsoft.AspNetCore.Identity;

namespace Co.Identity.Models;

public class ApplicationRole : IdentityRole
{
    public string? Description { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public bool IsActive { get; set; } = true;
} 