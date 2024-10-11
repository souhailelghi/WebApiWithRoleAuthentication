using StudentConsumerMicroservice.Models;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;

namespace StudentConsumerMicroservice.Services
{
    public class StudentServiceConsumer
    {
        private readonly HttpClient _httpClient;

        public StudentServiceConsumer(HttpClient httpClient)
        {
            _httpClient = httpClient;
        }

        // Method to check if the login is valid
        public async Task<bool> IsValidLoginAsync(string email, string password)
        {
            var loginRequest = new LoginRequest
            {
                Email = email,
                Password = password
            };

            var response = await _httpClient.PostAsJsonAsync("https://localhost:7010/api/Student/CheckEmailAndPassword", loginRequest);

            return response.IsSuccessStatusCode; // Return true if login is valid, otherwise false
        }

        // Method to get the student details if the login is valid
        public async Task<(string?, string?, string?)> GetStudentDetailsAsync(string email, string password)
        {
            var loginRequest = new LoginRequest
            {
                Email = email,
                Password = password
            };

            var response = await _httpClient.PostAsJsonAsync("https://localhost:7010/api/Student/CheckEmailAndPassword", loginRequest);

            if (response.IsSuccessStatusCode)
            {
                var studentDetails = await response.Content.ReadFromJsonAsync<StudentDetailsResponse>();
                return (studentDetails?.CodeUIR, studentDetails?.FirstName, studentDetails?.LastName); // Return student details
            }

            return (null, null, null); // Unauthorized or other error
        }
    }
}
