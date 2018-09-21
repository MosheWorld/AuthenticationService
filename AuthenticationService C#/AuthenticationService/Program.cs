using System;
using System.Linq;
using System.Security.Claims;
using System.Collections.Generic;
using AuthenticationService.Models;
using AuthenticationService.Managers;

namespace AuthenticationService
{
    class Program
    {
        static void Main(string[] args)
        {
            IAuthContainerModel model = GetJWTContainerModel("Moshe Binieli", "mmoshikoo@gmail.com");
            IAuthService authService = new JWTService(model.SecretKey);

            string token = authService.GenerateToken(model);

            if (!authService.IsTokenValid(token))
                throw new UnauthorizedAccessException();
            else
            {
                List<Claim> claims = authService.GetTokenClaims(token).ToList();

                Console.WriteLine(claims.FirstOrDefault(e => e.Type.Equals(ClaimTypes.Name)).Value);
                Console.WriteLine(claims.FirstOrDefault(e => e.Type.Equals(ClaimTypes.Email)).Value);
            }
        }

        #region Private Methods
        private static JWTContainerModel GetJWTContainerModel(string name, string email)
        {
            return new JWTContainerModel()
            {
                Claims = new Claim[]
                {
                    new Claim(ClaimTypes.Name, name),
                    new Claim(ClaimTypes.Email, email)
                }
            };
        }
        #endregion
    }
}
