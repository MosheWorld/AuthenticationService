using System.Security.Claims;

namespace AuthenticationService.Models;

public interface IAuthContainerModel
{
    int ExpireMinutes { get; }

    IReadOnlyCollection<Claim> Claims { get; }
}
