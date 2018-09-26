using System.Security.Claims;
using AuthenticationService.Models;

namespace AuthenticationService.Managers;

public interface IAuthService
{
    string GenerateToken(IAuthContainerModel model);

    ClaimsPrincipal ValidateToken(string token);
}
