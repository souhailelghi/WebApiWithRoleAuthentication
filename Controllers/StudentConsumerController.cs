using Microsoft.AspNetCore.Mvc;
using StudentConsumerMicroservice.Models;
using StudentConsumerMicroservice.Services;
using System.Threading.Tasks;

namespace StudentConsumerMicroservice.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class StudentConsumerController : ControllerBase
    {
        private readonly StudentServiceConsumer _studentServiceConsumer;

        public StudentConsumerController(StudentServiceConsumer studentServiceConsumer)
        {
            _studentServiceConsumer = studentServiceConsumer;
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
    }
}
