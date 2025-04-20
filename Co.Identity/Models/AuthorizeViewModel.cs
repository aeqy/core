namespace Co.Identity.Models;

public class AuthorizeViewModel
{
    public string ApplicationName { get; set; } = string.Empty;
    public string RequestId { get; set; } = string.Empty;
    public List<ScopeViewModel> Scopes { get; set; } = new List<ScopeViewModel>();
}

public class ScopeViewModel
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
} 