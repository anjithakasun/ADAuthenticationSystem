using ADAuthentication.PL.Models;
using ADAuthentication.PL.Services;
using Microsoft.AspNetCore.Mvc;
using System.DirectoryServices.ActiveDirectory;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace ADAuthentication.Controllers
{
    [Route("api/ADAuthenitcaion")]
    [ApiController]
    public class ADAuthenitcaionController : ControllerBase
    {
        private readonly ActiveDirectoryService _ad;
        public ADAuthenitcaionController(ActiveDirectoryService ad)
        {
            _ad = ad;
        }

        [HttpPost]
        [Route("Authentication")]
        public async Task<IActionResult> Login(string username, string password)
        {
            var user = _ad.AuthenticateAndGetUser(username, password);
            ApiResponse<ADUserModel> model = new ApiResponse<ADUserModel>();

            if (user == null)
            {
                model.Status = false;
                model.Message = "Invalid login";
                model.Data = null;
                return Unauthorized(model);
            }

            return Ok(user); // send AD attributes to frontend / API consumer
        }       
    }
}
