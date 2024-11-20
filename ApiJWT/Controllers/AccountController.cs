using ApiJWT.Data;
using ApiJWT.Dtos;
using ApiJWT.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace ApiJWT.Models
{
    [Route("api/[controller]")]
    [ApiController]
    public partial class AccountController : ControllerBase
    {
        private readonly ApplicationContext _context;
        private readonly IConfiguration _configuration;

        public AccountController(IConfiguration configuration, ApplicationContext context)
        {
            _configuration = configuration;
            _context = context;
        }

        /// <summary>
        /// Method for register user
        /// </summary>
        /// <param name="registerDto">Data of user</param>
        /// <response code="201">New users registred</response>
        /// <response code="400">Bad Request</response>
        [HttpPost("register")]
        [ProducesResponseType(StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> Register(RegisterDto registerDto)
        {
            _context.BrosShopUsers.Add(new BrosShopUser
            {
                BrosShopUsername = registerDto.Username,
                BrosShopEmail = registerDto.Email,
                BrosShopPassword = registerDto.Password // Не забудьте хешировать пароль!
            });
            await _context.SaveChangesAsync();
            return Ok(new { message = "Success" });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginDto loginDto)
        {
            var userEntity = await _context.BrosShopUsers
                .Include(u => u.RefreshTokens) // Include refresh tokens
                .FirstOrDefaultAsync(u => u.BrosShopUsername == loginDto.Username);

            if (userEntity != null && userEntity.BrosShopPassword == loginDto.Password) // Add password validation
            {
                var authClaims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, userEntity.BrosShopUsername!),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        };

                var token = GenerateToken(_configuration["Jwt:Key"], authClaims, double.Parse(_configuration["Jwt:ExpiryMinutes"]!));
                var refreshToken = GenerateRefreshToken(userEntity);

                return Ok(new { Token = token, RefreshToken = refreshToken.Token });
            }
            return Unauthorized();
        }

        [AllowAnonymous]
        [HttpPost("refresh")]
        public async Task<ActionResult<LoginResponse>> Refresh([FromBody] RefreshRequest request)
        {
            var userId = GetUserIdFromAccessToken(request.AccessToken);
            var user = await _context.BrosShopUsers
                .Include(u => u.RefreshTokens)
                .FirstOrDefaultAsync(u => u.BrosShopUsername == userId);

            ValidateRefreshToken(user, request.RefreshToken);

            var authClaims = new List<Claim>
            {
            new Claim(JwtRegisteredClaimNames.Sub, user.BrosShopUsername!),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
             };

            var newAccessToken = GenerateToken(_configuration["Jwt:Key"], authClaims, double.Parse(_configuration["Jwt:ExpiryMinutes"]!));
            var newRefreshToken = GenerateRefreshToken(user);

            return new LoginResponse
            {
                AccessToken = newAccessToken,
                AccessTokenExpiration = DateTime.UtcNow.AddMinutes(double.Parse(_configuration["Jwt:ExpiryMinutes"]!)),
                RefreshToken = newRefreshToken.Token
            };
        }

        private RefreshToken GenerateRefreshToken(BrosShopUser user)
        {
            var refreshToken = new RefreshToken
            {
                Token = GenerateRandomTokenString(), // Call the renamed method
                Expiration = DateTime.UtcNow.AddMinutes(3) // Configurable expiration
            };

            user.RefreshTokens.Add(refreshToken);
            _context.Update(user);
            _context.SaveChanges();

            return refreshToken;
        }

        private string GenerateRandomTokenString() // Renamed method
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        private void ValidateRefreshToken(BrosShopUser user, string refreshToken)
        {
            if (user == null || !user.RefreshTokens.Any(rt => rt.Token == refreshToken))
            {
                throw new SecurityTokenException("Invalid token!");
            }

            var storedRefreshToken = user.RefreshTokens.First(rt => rt.Token == refreshToken);
            if (DateTime.UtcNow > storedRefreshToken.Expiration)
            {
                throw new SecurityTokenException("Invalid token!");
            }
        }
        private string GenerateToken(string appSecret, IEnumerable<Claim> claims, double expirationInMinutes)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(appSecret);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddMinutes(expirationInMinutes),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private string GetUserIdFromAccessToken(string accessToken)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = true,
                ValidateLifetime = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!))
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;

            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token!");
            }

            var userId = principal.FindFirst(ClaimTypes.Name)?.Value;

            if (string.IsNullOrEmpty(userId))
            {
                throw new SecurityTokenException($"Missing claim: {ClaimTypes.Name}!");
            }

            return userId;
        }
    }
}