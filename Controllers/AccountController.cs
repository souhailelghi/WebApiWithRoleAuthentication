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

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] Login model)
        {
            // Find user by email
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                // Get the user's roles
                var userRoles = await _userManager.GetRolesAsync(user);

                // Check if the user has a valid role (SuperAdmin or Admin)
                if (!userRoles.Any(role => role == "SuperAdmin" || role == "Admin"))
                {
                    return Unauthorized(new { message = "Access denied. Only SuperAdmin or Admin can log in." });
                }

                // Create claims for the JWT token
                var authClaims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Email!),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim("UserId", user.Id),
            new Claim("UserName", user.UserName!)
        };

                authClaims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

                // Generate the JWT token
                var token = new JwtSecurityToken(
                    issuer: _configuration["Jwt:Issuer"],
                    expires: DateTime.Now.AddMinutes(double.Parse(_configuration["Jwt:ExpiryMinutes"]!)),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(
                        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!)),
                        SecurityAlgorithms.HmacSha256
                    )
                );

                // Define permissions based on roles
                var permissions = userRoles.Contains("SuperAdmin")
                    ? new[] { "Create", "Read", "Update", "Delete" }
                    : new[] { "Read" };

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    id = user.Id,
                    userName = user.UserName,
                    roles = userRoles,
                    permissions
                });
            }

            return Unauthorized(new { message = "Invalid email or password." });
        }




        [HttpPost("loginSuperAdmin")]
        //login superadmin :
        public async Task<IActionResult> LoginSuperAdmin([FromBody] Login model)
        {
            // Find user by email
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                // Get the user's roles and check if they have the "SuperAdmin" role
                var userRoles = await _userManager.GetRolesAsync(user);
                if (!userRoles.Contains("SuperAdmin"))
                {
                    return Unauthorized(new { message = "Access denied. Only SuperAdmins can log in." });
                }

                // Create claims for the JWT token
                var authClaims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Email!),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim("UserId", user.Id),
            new Claim("UserName", user.UserName!)
        };

                authClaims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

                // Generate the JWT token
                var token = new JwtSecurityToken(
                    issuer: _configuration["Jwt:Issuer"],
                    expires: DateTime.Now.AddMinutes(double.Parse(_configuration["Jwt:ExpiryMinutes"]!)),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(
                        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!)),
                        SecurityAlgorithms.HmacSha256
                    )
                );

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    id = user.Id,
                    userName = user.UserName
                });
            }

            return Unauthorized(new { message = "Invalid email or password." });
        }




        // -------------

     

        
        [HttpPost("loginAdmin")]
        //login admin : 
        public async Task<IActionResult> LoginAdmin([FromBody] Login model)
        {
            // Find user by email
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                // Get the user's roles and check if they have the "Admin" role
                var userRoles = await _userManager.GetRolesAsync(user);
                if (!userRoles.Contains("Admin"))
                {
                    return Unauthorized(new { message = "Access denied. Only admins can log in." });
                }

                // Create claims for the JWT token
                var authClaims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Email!),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim("UserId", user.Id),
            new Claim("UserName", user.UserName!)
        };

                authClaims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

                // Generate the JWT token
                var token = new JwtSecurityToken(
                    issuer: _configuration["Jwt:Issuer"],
                    expires: DateTime.Now.AddMinutes(double.Parse(_configuration["Jwt:ExpiryMinutes"]!)),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(
                        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!)),
                        SecurityAlgorithms.HmacSha256
                    )
                );

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    id = user.Id,
                    userName = user.UserName
                });
            }

            return Unauthorized(new { message = "Invalid email or password." });
        }


        [HttpPost("registerAdmin")]
        //register admin :
        public async Task<IActionResult> RegisterAdmin([FromBody] Register model)
        {
            // Check if the "Admin" role exists; create it if it doesn't
            if (!await _roleManager.RoleExistsAsync("Admin"))
            {
                var roleResult = await _roleManager.CreateAsync(new IdentityRole("Admin"));
                if (!roleResult.Succeeded)
                {
                    return BadRequest(new { Message = "Failed to create 'Admin' role" });
                }
            }

            // Create the new admin user
            var adminUser = new IdentityUser { UserName = model.Username, Email = model.Email };
            var result = await _userManager.CreateAsync(adminUser, model.Password);

            if (result.Succeeded)
            {
                // Assign the "Admin" role to the user
                var roleAssignResult = await _userManager.AddToRoleAsync(adminUser, "Admin");
                if (!roleAssignResult.Succeeded)
                {
                    return BadRequest(new { Message = "Failed to assign 'Admin' role" });
                }

                // Generate claims and a JWT token for the new admin user
                var authClaims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, adminUser.Email!),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Name, adminUser.UserName!),
            new Claim("UserId", adminUser.Id)
        };

                authClaims.Add(new Claim(ClaimTypes.Role, "Admin"));

                var token = new JwtSecurityToken(
                    issuer: _configuration["Jwt:Issuer"],
                    expires: DateTime.Now.AddMinutes(double.Parse(_configuration["Jwt:ExpiryMinutes"]!)),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(
                        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!)),
                        SecurityAlgorithms.HmacSha256
                    )
                );

                return Ok(new
                {
                    Message = "Admin registered successfully",
                    Token = new JwtSecurityTokenHandler().WriteToken(token),
                    UserName = adminUser.UserName
                });
            }

            return BadRequest(result.Errors);
        }


        [HttpPost("registerSuperAdmin")]
        //register super admin :
        public async Task<IActionResult> RegisterSuperAdmin([FromBody] Register model)
        {
            // Check if the "SuperAdmin" role exists; create it if it doesn't
            if (!await _roleManager.RoleExistsAsync("SuperAdmin"))
            {
                var roleResult = await _roleManager.CreateAsync(new IdentityRole("SuperAdmin"));
                if (!roleResult.Succeeded)
                {
                    return BadRequest(new { Message = "Failed to create 'SuperAdmin' role" });
                }
            }

            // Create the new SuperAdmin user
            var superAdminUser = new IdentityUser { UserName = model.Username, Email = model.Email };
            var result = await _userManager.CreateAsync(superAdminUser, model.Password);

            if (result.Succeeded)
            {
                // Assign the "SuperAdmin" role to the user
                var roleAssignResult = await _userManager.AddToRoleAsync(superAdminUser, "SuperAdmin");
                if (!roleAssignResult.Succeeded)
                {
                    return BadRequest(new { Message = "Failed to assign 'SuperAdmin' role" });
                }

                // Generate claims and a JWT token for the new SuperAdmin user
                var authClaims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, superAdminUser.Email!),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Name, superAdminUser.UserName!),
            new Claim("UserId", superAdminUser.Id)
        };

                authClaims.Add(new Claim(ClaimTypes.Role, "SuperAdmin"));

                var token = new JwtSecurityToken(
                    issuer: _configuration["Jwt:Issuer"],
                    expires: DateTime.Now.AddMinutes(double.Parse(_configuration["Jwt:ExpiryMinutes"]!)),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(
                        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!)),
                        SecurityAlgorithms.HmacSha256
                    )
                );

                return Ok(new
                {
                    Message = "SuperAdmin registered successfully",
                    Token = new JwtSecurityTokenHandler().WriteToken(token),
                    UserName = superAdminUser.UserName
                });
            }

            return BadRequest(result.Errors);
        }






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


        [HttpGet("get-username/{id}")]
        public async Task<IActionResult> GetUsernameById(string id)
        {
            var user = await _userManager.FindByIdAsync(id);
            if (user == null)
            {
                return NotFound(new { Message = "User not found" });
            }
            return Ok(new { Username = user.UserName });
        }




    }
}
