using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using WebApiWithRoleAuthentication.Dto;
using WebApiWithRoleAuthentication.Services;

namespace WebApiWithRoleAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AuthService _authService;

        public AuthController(AuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            var authResult = await _authService.AuthenticateAsync(loginDto.Username, loginDto.Password);
            if (authResult == null)
                return Unauthorized(new { message = "Invalid username or password" });

            // Check if authResult has a value
            var result = authResult.Value; // Extract the tuple from the nullable type

            return Ok(new { Token = result.Token, UserId = result.UserId }); // Include User ID in response
        }


    }
}
