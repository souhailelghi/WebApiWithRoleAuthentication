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

        //    [HttpPost("registerAutomaticallyAndLoginAutomatically")]
        //    public async Task<IActionResult> RegisterAutomaticallyAndLoginAutomatically([FromBody] RegisterUser model)
        //    {
        //        // Check if the email exists using StudentServiceConsumer
        //        var isValid = await _studentServiceConsumer.IsValidLoginAsync(model.Email, model.Password);

        //        if (isValid)
        //        {
        //            // Check if the user already exists in Identity
        //            var existingUser = await _userManager.FindByEmailAsync(model.Email);

        //            if (existingUser != null)
        //            {
        //                // If the user exists, validate their password and log them in
        //                if (await _userManager.CheckPasswordAsync(existingUser, model.Password))
        //                {
        //                    var token = await GenerateJwtToken(existingUser); // Generate the JWT token
        //                    return Ok(new { Token = token, UserId = existingUser.Id });
        //                }

        //                return BadRequest(new { Message = "Invalid credentials" });
        //            }

        //            // If the user doesn't exist, create a new IdentityUser
        //            var newUser = new IdentityUser { Email = model.Email, UserName = model.Email };
        //            var createResult = await _userManager.CreateAsync(newUser, model.Password);

        //            if (createResult.Succeeded)
        //            {
        //                // Ensure the "User" role exists in the system
        //                if (!await _roleManager.RoleExistsAsync("User"))
        //                {
        //                    var roleResult = await _roleManager.CreateAsync(new IdentityRole("User"));
        //                    if (!roleResult.Succeeded)
        //                    {
        //                        return BadRequest(new { Message = "Failed to create 'User' role" });
        //                    }
        //                }

        //                // Assign the "User" role to the newly created user
        //                var roleAssignResult = await _userManager.AddToRoleAsync(newUser, "User");

        //                if (!roleAssignResult.Succeeded)
        //                {
        //                    return BadRequest(new { Message = "Failed to assign 'User' role" });
        //                }

        //                // Generate and return the JWT token for the new user
        //                var token = await GenerateJwtToken(newUser); // Method to generate token
        //                return Ok(new { Token = token, UserId = newUser.Id });
        //            }

        //            // Return errors if the user creation failed
        //            return BadRequest(createResult.Errors);
        //        }

        //        // Return an error if the StudentService validation failed
        //        return BadRequest(new { Message = "Invalid email or password in StudentService." });
        //    }

        //    // Helper method to generate the JWT token
        //    private async Task<string> GenerateJwtToken(IdentityUser user)
        //    {
        //        var authClaims = new List<Claim>
        //{
        //    new Claim(JwtRegisteredClaimNames.Sub, user.Email!), // Use Email as Subject
        //    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        //};

        //        // Get the user roles and add them to the claims
        //        var userRoles = await _userManager.GetRolesAsync(user);
        //        authClaims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

        //        var token = new JwtSecurityToken(
        //            issuer: _configuration["Jwt:Issuer"],
        //            expires: DateTime.Now.AddMinutes(double.Parse(_configuration["Jwt:ExpiryMinutes"]!)),
        //            claims: authClaims,
        //            signingCredentials: new SigningCredentials(
        //                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!)),
        //                SecurityAlgorithms.HmacSha256)
        //        );

        //        return new JwtSecurityTokenHandler().WriteToken(token);
        //    }



        [HttpPost("registerAutomaticallyAndLoginAutomatically")]
        public async Task<IActionResult> RegisterAutomaticallyAndLoginAutomatically([FromBody] RegisterUser model)
        {
            // Check if the email exists using StudentServiceConsumer
            var isValid = await _studentServiceConsumer.IsValidLoginAsync(model.Email, model.Password);

            if (isValid)
            {
                // Check if the user already exists in Identity
                var existingUser = await _userManager.FindByEmailAsync(model.Email);

                if (existingUser != null)
                {
                    // If the user exists, validate their password and log them in
                    if (await _userManager.CheckPasswordAsync(existingUser, model.Password))
                    {
                        var token = await GenerateJwtToken(existingUser); // Generate the JWT token
                        return Ok(new { Token = token, UserId = existingUser.Id });
                    }

                    return BadRequest(new { Message = "Invalid credentials" });
                }

                // If the user doesn't exist, create a new IdentityUser
                var newUser = new IdentityUser { Email = model.Email, UserName = model.Email };
                var createResult = await _userManager.CreateAsync(newUser, model.Password);

                if (createResult.Succeeded)
                {
                    // Ensure the "User" role exists in the system
                    if (!await _roleManager.RoleExistsAsync("User"))
                    {
                        var roleResult = await _roleManager.CreateAsync(new IdentityRole("User"));
                        if (!roleResult.Succeeded)
                        {
                            return BadRequest(new { Message = "Failed to create 'User' role" });
                        }
                    }

                    // Assign the "User" role to the newly created user
                    var roleAssignResult = await _userManager.AddToRoleAsync(newUser, "User");

                    if (!roleAssignResult.Succeeded)
                    {
                        return BadRequest(new { Message = "Failed to assign 'User' role" });
                    }

                    // Get the student details from the StudentServiceConsumer
                    var (codeUIR, firstName, lastName) = await _studentServiceConsumer.GetStudentDetailsAsync(model.Email, model.Password);

                    // Generate and return the JWT token for the new user
                    var token = await GenerateJwtToken(newUser); // Method to generate token
                    return Ok(new
                    {
                        Token = token,
                        UserId = newUser.Id,
                        CodeUIR = codeUIR,
                        FirstName = firstName,
                        LastName = lastName
                    });
                }

                // Return errors if the user creation failed
                return BadRequest(createResult.Errors);
            }

            // Return an error if the StudentService validation failed
            return BadRequest(new { Message = "Invalid email or password in StudentService." });
        }

        //is work : 
        //[HttpPost("registerAutomaticallyAndLoginAutomatically")]
        //public async Task<IActionResult> RegisterAutomaticallyAndLoginAutomatically([FromBody] RegisterUser model)
        //{
        //    // Check if the email exists using StudentServiceConsumer
        //    var isValid = await _studentServiceConsumer.IsValidLoginAsync(model.Email, model.Password);

        //    if (isValid)
        //    {
        //        // Check if the user already exists in Identity
        //        var existingUser = await _userManager.FindByEmailAsync(model.Email);

        //        if (existingUser != null)
        //        {
        //            // If the user exists, validate their password and log them in
        //            if (await _userManager.CheckPasswordAsync(existingUser, model.Password))
        //            {
        //                var (codeUIR, firstName, lastName) = await _studentServiceConsumer.GetStudentDetailsAsync(model.Email, model.Password);
        //                var token = await GenerateJwtToken(existingUser); // Generate the JWT token
        //                return Ok(new { Token = token, UserId = existingUser.Id, CodeUIR = codeUIR, FirstName = firstName, LastName = lastName });
        //            }

        //            return BadRequest(new { Message = "Invalid credentials" });
        //        }

        //        // If the user doesn't exist, create a new IdentityUser
        //        var newUser = new IdentityUser { Email = model.Email, UserName = model.Email };
        //        var createResult = await _userManager.CreateAsync(newUser, model.Password);

        //        if (createResult.Succeeded)
        //        {
        //            // Ensure the "User" role exists in the system
        //            if (!await _roleManager.RoleExistsAsync("User"))
        //            {
        //                var roleResult = await _roleManager.CreateAsync(new IdentityRole("User"));
        //                if (!roleResult.Succeeded)
        //                {
        //                    return BadRequest(new { Message = "Failed to create 'User' role" });
        //                }
        //            }

        //            // Assign the "User" role to the newly created user
        //            var roleAssignResult = await _userManager.AddToRoleAsync(newUser, "User");

        //            if (!roleAssignResult.Succeeded)
        //            {
        //                return BadRequest(new { Message = "Failed to assign 'User' role" });
        //            }

        //            // Generate and return the JWT token for the new user
        //            var token = await GenerateJwtToken(newUser); // Method to generate token
        //            var (codeUIR, firstName, lastName) = await _studentServiceConsumer.GetStudentDetailsAsync(model.Email, model.Password);
        //            return Ok(new { Token = token, UserId = newUser.Id, CodeUIR = codeUIR, FirstName = firstName, LastName = lastName });
        //        }

        //        // Return errors if the user creation failed
        //        return BadRequest(createResult.Errors);
        //    }

        //    // Return an error if the StudentService validation failed
        //    return BadRequest(new { Message = "Invalid email or password in StudentService." });
        //}

        // Helper method to generate the JWT token
        private async Task<string> GenerateJwtToken(IdentityUser user)
        {
            var authClaims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Email!), // Use Email as Subject
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            // Get the user roles and add them to the claims
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


    

    }
}
