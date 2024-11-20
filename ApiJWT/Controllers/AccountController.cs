using ApiJWT.Data;
using ApiJWT.Dtos;
using ApiJWT.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthWithRoles.Controllers.v1
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly ApplicationContext _context;
        private readonly IConfiguration _configuration;

        public AccountController( IConfiguration configuration, ApplicationContext context)
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
            return  Ok(new { message = "Success" }) ;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginDto loginDto)
        {
            var userEntity = await _context.BrosShopUsers
             .FirstOrDefaultAsync(u => u.BrosShopUsername == loginDto.Username);
            if (userEntity != null)
            {

                var authClaims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Sub, userEntity.BrosShopUsername!),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };


                var token = new JwtSecurityToken(
                    issuer: _configuration["Jwt:Issuer"],
                    expires: DateTime.Now.AddMinutes(double.Parse(_configuration["Jwt:ExpiryMinutes"]!)),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(
                        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!)), SecurityAlgorithms.HmacSha256)
                    );

                return Ok(new { Token = new JwtSecurityTokenHandler().WriteToken(token) });
            }
            return Unauthorized();
        }
    }
}