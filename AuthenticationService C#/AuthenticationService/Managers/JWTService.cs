using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthenticationService.Models;
using Microsoft.IdentityModel.Tokens;

namespace AuthenticationService.Managers;

public sealed class JWTService : IAuthService
{
    private const string SigningAlgorithm = SecurityAlgorithms.HmacSha256;

    private readonly SymmetricSecurityKey _signingKey;
    private readonly string _issuer;
    private readonly string _audience;

    public JWTService(string secretKey, string issuer, string audience)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secretKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);

        byte[] keyBytes = Encoding.UTF8.GetBytes(secretKey);

        if (keyBytes.Length < 32)
        {
            throw new ArgumentException(
                "The HS256 signing key must contain at least 32 bytes.",
                nameof(secretKey));
        }

        _signingKey = new SymmetricSecurityKey(keyBytes);
        _issuer = issuer;
        _audience = audience;
    }

    public string GenerateToken(IAuthContainerModel model)
    {
        ArgumentNullException.ThrowIfNull(model);

        if (model.Claims.Count == 0)
        {
            throw new ArgumentException(
                "At least one claim is required to create a token.",
                nameof(model));
        }

        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = _issuer,
            Audience = _audience,
            Subject = new ClaimsIdentity(model.Claims),
            Expires = DateTime.UtcNow.AddMinutes(model.ExpireMinutes),
            SigningCredentials = new SigningCredentials(_signingKey, SigningAlgorithm)
        };

        var tokenHandler = CreateTokenHandler();
        SecurityToken token = tokenHandler.CreateToken(descriptor);

        return tokenHandler.WriteToken(token);
    }

    public ClaimsPrincipal ValidateToken(string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        var validationParameters = new TokenValidationParameters
        {
            RequireSignedTokens = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = _signingKey,
            ValidAlgorithms = [SigningAlgorithm],
            ValidTypes = ["JWT"],

            ValidateIssuer = true,
            ValidIssuer = _issuer,

            ValidateAudience = true,
            ValidAudience = _audience,

            RequireExpirationTime = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(1)
        };

        return CreateTokenHandler().ValidateToken(
            token,
            validationParameters,
            out _);
    }

    private static JwtSecurityTokenHandler CreateTokenHandler()
    {
        return new JwtSecurityTokenHandler
        {
            MapInboundClaims = false
        };
    }
}
