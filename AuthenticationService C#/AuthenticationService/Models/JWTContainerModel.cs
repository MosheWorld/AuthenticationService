using System.Security.Claims;

namespace AuthenticationService.Models;

public sealed class JWTContainerModel : IAuthContainerModel
{
    public JWTContainerModel(IEnumerable<Claim> claims, int expireMinutes)
    {
        ArgumentNullException.ThrowIfNull(claims);

        if (expireMinutes <= 0)
        {
            throw new ArgumentOutOfRangeException(
                nameof(expireMinutes),
                "Token expiration must be greater than zero minutes.");
        }

        Claim[] claimArray = claims.ToArray();

        if (claimArray.Length == 0)
        {
            throw new ArgumentException(
                "At least one claim is required.",
                nameof(claims));
        }

        if (claimArray.Any(static claim => claim is null))
        {
            throw new ArgumentException(
                "Claims cannot contain null values.",
                nameof(claims));
        }

        Claims = Array.AsReadOnly(claimArray);

        ExpireMinutes = expireMinutes;
    }

    public int ExpireMinutes { get; }

    public IReadOnlyCollection<Claim> Claims { get; }
}
