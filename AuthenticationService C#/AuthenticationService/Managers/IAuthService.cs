using System.Security.Claims;
using System.Collections.Generic;
using AuthenticationService.Models;

namespace AuthenticationService.Managers
{
    public interface IAuthService
    {
        string SecretKey { get; set; }

        bool IsTokenValid(string token);
        string GenerateToken(IAuthContainerModel model);
        IEnumerable<Claim> GetTokenClaims(string token);
    }
}
