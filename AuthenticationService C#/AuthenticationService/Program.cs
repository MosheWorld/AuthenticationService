using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using AuthenticationService.Managers;
using AuthenticationService.Models;

namespace AuthenticationService;

internal static class Program
{
    // This fixed key is intentionally visible because this is a teaching project.
    // Production applications must load signing keys from a secure secret store.
    private const string DemoSigningKey =
        "demo-only-secret-do-not-use-in-production";

    private const string DemoIssuer = "AuthenticationService.TeachingDemo";
    private const string DemoAudience = "AuthenticationService.Students";

    private static void Main()
    {
        IAuthContainerModel model = new JWTContainerModel(
            claims:
            [
                new Claim(JwtRegisteredClaimNames.Name, "Moshe Binieli"),
                new Claim(JwtRegisteredClaimNames.Email, "mmoshikoo@gmail.com")
            ],
            expireMinutes: 15);

        IAuthService authService = new JWTService(
            DemoSigningKey,
            DemoIssuer,
            DemoAudience);

        string token = authService.GenerateToken(model);
        ClaimsPrincipal principal = authService.ValidateToken(token);

        Console.WriteLine("Generated JWT:");
        Console.WriteLine(token);
        Console.WriteLine();
        Console.WriteLine("Validated claims:");
        Console.WriteLine($"Name: {GetRequiredClaim(principal, JwtRegisteredClaimNames.Name)}");
        Console.WriteLine($"Email: {GetRequiredClaim(principal, JwtRegisteredClaimNames.Email)}");
    }

    private static string GetRequiredClaim(ClaimsPrincipal principal, string claimType)
    {
        return principal.FindFirst(claimType)?.Value
            ?? throw new InvalidOperationException(
                $"The validated token does not contain the required '{claimType}' claim.");
    }
}
