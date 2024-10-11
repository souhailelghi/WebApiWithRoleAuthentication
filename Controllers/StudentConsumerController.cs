using Microsoft.AspNetCore.Mvc;
using WebApiWithRoleAuthentication.Models;
using WebApiWithRoleAuthentication.Services;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace WebApiWithRoleAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class StudentConsumerController : ControllerBase
    {
        private readonly StudentServiceConsumer _studentServiceConsumer;
        private readonly UserManager<IdentityUser> _userManager;

        public StudentConsumerController(StudentServiceConsumer studentServiceConsumer , UserManager<IdentityUser> userManager)
        {
            _studentServiceConsumer = studentServiceConsumer;
            _userManager = userManager;
        }

        [HttpPost("ValidateStudent")]
        public async Task<IActionResult> ValidateStudent([FromBody] LoginRequest loginRequest)
        {
            // First, check if the login is valid
            bool isValid = await _studentServiceConsumer.IsValidLoginAsync(loginRequest.Email, loginRequest.Password);

            if (isValid)
            {
                // If valid, get the student details
                var (codeUIR, firstName, lastName) = await _studentServiceConsumer.GetStudentDetailsAsync(loginRequest.Email, loginRequest.Password);
                return Ok(new { CodeUIR = codeUIR, FirstName = firstName, LastName = lastName });
            }

            // If login is not valid, return Unauthorized
            return Unauthorized(new { Message = "Invalid credentials" });
        }

        [HttpPost("registerAutomaticlly")]
        public async Task<IActionResult> RegisterAutomatically([FromBody] LoginRequest loginRequest)
        {
            // Check if the login is valid
            bool isValid = await _studentServiceConsumer.IsValidLoginAsync(loginRequest.Email, loginRequest.Password);

            if (!isValid)
            {
                return Unauthorized(new { Message = "Invalid credentials" });
            }

            // Create a new user
            var user = new IdentityUser { UserName = loginRequest.Email, Email = loginRequest.Email };
            var result = await _userManager.CreateAsync(user, loginRequest.Password);

            if (result.Succeeded)
            {
                // Assign the "User" role to the newly registered user
                await _userManager.AddToRoleAsync(user, "User");
                return Ok(new { Message = "User registered successfully" });
            }

            return BadRequest(result.Errors);
        }

    }
}
