using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using WebApiWithRoleAuthentication.Models;
using WebApiWithRoleAuthentication.Services;

namespace WebApiWithRoleAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly StudentServiceConsumer _studentServiceConsumer;

        public AccountController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration, StudentServiceConsumer studentServiceConsumer)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _studentServiceConsumer = studentServiceConsumer;

        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] Register model)
        {
            var user = new IdentityUser { UserName = model.Username, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                // Optionally add to a role if needed
                // await _userManager.AddToRoleAsync(user, "User");
                return Ok(new { message = "User registered successfully" });
            }

            return BadRequest(result.Errors);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Login model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var userRoles = await _userManager.GetRolesAsync(user);

                var authClaims = new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Sub, user.UserName!),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

                authClaims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

                var token = new JwtSecurityToken(
                    issuer: _configuration["Jwt:Issuer"],
                    expires: DateTime.Now.AddMinutes(double.Parse(_configuration["Jwt:ExpiryMinutes"]!)),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!)),
                    SecurityAlgorithms.HmacSha256));

                return Ok(new { token = new JwtSecurityTokenHandler().WriteToken(token) });
            }

            return Unauthorized();
        }

        //[HttpPost("registerAutomaticallyAndLoginAutomatically")]
        //public async Task<IActionResult> RegisterAutomaticallyAndLoginAutomatically([FromBody] Register model)
        //{
        //    // Check if the username is already taken
        //    var existingUser = await _userManager.FindByNameAsync(model.Username);
        //    if (existingUser != null)
        //    {
        //        return BadRequest(new { Message = "Username is already taken" });
        //    }

        //    // Register the user
        //    var user = new IdentityUser { UserName = model.Username, Email = model.Email };
        //    var result = await _userManager.CreateAsync(user, model.Password);

        //    if (result.Succeeded)
        //    {
        //        // Optionally add the user to a role
        //        // await _userManager.AddToRoleAsync(user, "User");

        //        // Automatically log in the user and generate JWT token
        //        var authClaims = new List<Claim>
        //        {
        //            new Claim(JwtRegisteredClaimNames.Sub, user.UserName!),
        //            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        //        };

        //        var token = new JwtSecurityToken(
        //            issuer: _configuration["Jwt:Issuer"],
        //            expires: DateTime.Now.AddMinutes(double.Parse(_configuration["Jwt:ExpiryMinutes"]!)),
        //            claims: authClaims,
        //            signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!)),
        //            SecurityAlgorithms.HmacSha256));

        //        return Ok(new { Token = new JwtSecurityTokenHandler().WriteToken(token), UserId = user.Id });
        //    }

        //    return BadRequest(result.Errors);
        //}



        [HttpPost("registerAutomaticallyAndLoginAutomatically")]
        public async Task<IActionResult> RegisterAutomaticallyAndLoginAutomatically([FromBody] RegisterUser model)
        {
            // Check if the user already exists
            var existingUser = await _userManager.FindByEmailAsync(model.Email);

            if (existingUser != null)
            {
                // Login if user already exists
                if (await _userManager.CheckPasswordAsync(existingUser, model.Password))
                {
                    var token = await GenerateJwtToken(existingUser); // Method to generate token
                    return Ok(new { Token = token, UserId = existingUser.Id });
                }
                return BadRequest(new { Message = "Invalid credentials" });
            }

            // Register the user
            var user = new IdentityUser { Email = model.Email, UserName = model.Email }; // Use email as username
            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                // Assign the "User" role automatically
                await _userManager.AddToRoleAsync(user, "User");

                // Automatically log in the user and generate JWT token
                var token = await GenerateJwtToken(user); // Method to generate token

                // Return token and user information
                return Ok(new { Token = token, UserId = user.Id });
            }

            return BadRequest(result.Errors);
        }

        // Helper method to generate the JWT token
        private async Task<string> GenerateJwtToken(IdentityUser user)
        {
            var authClaims = new List<Claim>
    {
        new Claim(JwtRegisteredClaimNames.Sub, user.Email!), // Use Email as Subject
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
    };

            // Get the user roles and add them to claims
            var userRoles = await _userManager.GetRolesAsync(user);
            authClaims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                expires: DateTime.Now.AddMinutes(double.Parse(_configuration["Jwt:ExpiryMinutes"]!)),
                claims: authClaims,
                signingCredentials: new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!)),
                    SecurityAlgorithms.HmacSha256)
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }





        //3


        //[HttpPost("registerAutomaticallyAndLoginAutomatically")]
        //public async Task<IActionResult> RegisterAutomaticallyAndLoginAutomatically([FromBody] RegisterUser model)
        //{
        //    // Check if the user exists in the authentication service
        //    var existingUser = await _userManager.FindByEmailAsync(model.Email);
        //    if (existingUser != null)
        //    {
        //        // User already exists, perform login and return token
        //        var loginUser = await _userManager.FindByEmailAsync(model.Email);
        //        if (loginUser != null && await _userManager.CheckPasswordAsync(loginUser, model.Password))
        //        {
        //            // Generate JWT token for existing user
        //            var authClaims = new List<Claim>
        //    {
        //        new Claim(JwtRegisteredClaimNames.Sub, loginUser.Email!), // Use Email as Subject
        //        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        //    };

        //            var token = new JwtSecurityToken(
        //                issuer: _configuration["Jwt:Issuer"],
        //                expires: DateTime.Now.AddMinutes(double.Parse(_configuration["Jwt:ExpiryMinutes"]!)),
        //                claims: authClaims,
        //                signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!)),
        //                SecurityAlgorithms.HmacSha256));

        //            return Ok(new
        //            {
        //                Token = new JwtSecurityTokenHandler().WriteToken(token),
        //                UserId = loginUser.Id,
        //                Message = "User logged in successfully"
        //            });
        //        }
        //        return Unauthorized(new { Message = "Invalid login credentials" });
        //    }

        //    // Check if the credentials are valid with StudentServiceConsumer
        //    bool isValid = await _studentServiceConsumer.IsValidLoginAsync(model.Email, model.Password);
        //    if (!isValid)
        //    {
        //        return Unauthorized(new { Message = "Invalid credentials with external system" });
        //    }

        //    // Register the user if they don't exist and credentials are valid
        //    var newUser = new IdentityUser { UserName = model.Email, Email = model.Email };
        //    var result = await _userManager.CreateAsync(newUser, model.Password);

        //    if (result.Succeeded)
        //    {
        //        // Optionally assign a role if needed
        //        // await _userManager.AddToRoleAsync(newUser, "User");

        //        // Get student details from external service
        //        var (codeUIR, firstName, lastName) = await _studentServiceConsumer.GetStudentDetailsAsync(model.Email, model.Password);

        //        // Generate JWT token for newly registered user
        //        var authClaims = new List<Claim>
        //{
        //    new Claim(JwtRegisteredClaimNames.Sub, newUser.Email!), // Use Email as Subject
        //    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        //};

        //        var token = new JwtSecurityToken(
        //            issuer: _configuration["Jwt:Issuer"],
        //            expires: DateTime.Now.AddMinutes(double.Parse(_configuration["Jwt:ExpiryMinutes"]!)),
        //            claims: authClaims,
        //            signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!)),
        //            SecurityAlgorithms.HmacSha256));

        //        // Return token, user ID, and student details
        //        return Ok(new
        //        {
        //            Token = new JwtSecurityTokenHandler().WriteToken(token),
        //            UserId = newUser.Id,
        //            CodeUIR = codeUIR,
        //            FirstName = firstName,
        //            LastName = lastName,
        //            Message = "User registered and logged in successfully"
        //        });
        //    }

        //    return BadRequest(result.Errors);
        //}

        //2

        //[HttpPost("registerAutomaticallyAndLoginAutomaticallytwo")]
        //public async Task<IActionResult> RegisterAutomaticallyAndLoginAutomaticallytwo([FromBody] RegisterUser model)
        //{
        //    // Check if the email is already taken
        //    var existingUser = await _userManager.FindByEmailAsync(model.Email);
        //    if (existingUser != null)
        //    {
        //        return BadRequest(new { Message = "Email is already taken" });
        //    }

        //    // Register the user
        //    var user = new IdentityUser { Email = model.Email, UserName = model.Email }; // Use Email as Username
        //    var result = await _userManager.CreateAsync(user, model.Password);

        //    if (result.Succeeded)
        //    {
        //        // Automatically log in the user and generate JWT token
        //        var authClaims = new List<Claim>
        //        {
        //            new Claim(JwtRegisteredClaimNames.Sub, user.Email!), // Use Email as Subject
        //            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        //        };

        //        var token = new JwtSecurityToken(
        //            issuer: _configuration["Jwt:Issuer"],
        //            expires: DateTime.Now.AddMinutes(double.Parse(_configuration["Jwt:ExpiryMinutes"]!)),
        //            claims: authClaims,
        //            signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!)),
        //            SecurityAlgorithms.HmacSha256));

        //        return Ok(new { Token = new JwtSecurityTokenHandler().WriteToken(token), UserId = user.Id });
        //    }

        //    return BadRequest(result.Errors);
        //}
        [HttpPost("add-role")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> AddRole([FromBody] string role)
        {
            if (!await _roleManager.RoleExistsAsync(role))
            {
                var result = await _roleManager.CreateAsync(new IdentityRole(role));
                if (result.Succeeded)
                {
                    return Ok(new { message = "Role added successfully" });
                }

                return BadRequest(result.Errors);
            }

            return BadRequest("Role already exists");
        }

        [HttpPost("assign-role")]
        [Authorize(Roles = "Admin")]  // Ensure only Admins can assign roles
        public async Task<IActionResult> AssignRole([FromBody] UserRole model)
        {
            var user = await _userManager.FindByNameAsync(model.Username);
            if (user == null)
            {
                return BadRequest("User not found");
            }

            var result = await _userManager.AddToRoleAsync(user, model.Role);
            if (result.Succeeded)
            {
                return Ok(new { message = "Role assigned successfully" });
            }

            return BadRequest(result.Errors);
        }


        //1
        //[HttpPost("registerAutomaticallyAndLoginAutomatically")]
        //public async Task<IActionResult> RegisterAutomaticallyAndLoginAutomatically([FromBody] RegisterUser model)
        //{
        //    // Check if the email is already taken
        //    var existingUser = await _userManager.FindByEmailAsync(model.Email);
        //    if (existingUser != null)
        //    {
        //        return BadRequest(new { Message = "Email is already taken" });
        //    }

        //    // Register the user
        //    var user = new IdentityUser { Email = model.Email, UserName = model.Email }; // Use Email as Username
        //    var result = await _userManager.CreateAsync(user, model.Password);

        //    if (result.Succeeded)
        //    {
        //        // Automatically log in the user and generate JWT token
        //        var authClaims = new List<Claim>
        //        {
        //            new Claim(JwtRegisteredClaimNames.Sub, user.Email!), // Use Email as Subject
        //            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        //        };

        //        var token = new JwtSecurityToken(
        //            issuer: _configuration["Jwt:Issuer"],
        //            expires: DateTime.Now.AddMinutes(double.Parse(_configuration["Jwt:ExpiryMinutes"]!)),
        //            claims: authClaims,
        //            signingCredentials: new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!)),
        //            SecurityAlgorithms.HmacSha256));

        //        return Ok(new { Token = new JwtSecurityTokenHandler().WriteToken(token), UserId = user.Id });
        //    }

        //    return BadRequest(result.Errors);
        //}

    }
}
