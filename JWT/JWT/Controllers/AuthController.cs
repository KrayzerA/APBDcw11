using JWT.Exceptions;
using JWT.Helpers;
using JWT.RequestModels;
using JWT.Servicies;
using JWT.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JWT.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthController(IAuthService service) : ControllerBase
{
    [HttpPost("login")]
    public IResult Login(LoginRequestModel request)
    {
        try
        {
            return Results.Ok(service.LoginUser(request));
        }
        catch (IncorrectPasswordException e)
        {
            return Results.Unauthorized();
        }
    }

    [AllowAnonymous]
    [HttpPost("register")]
    public IResult Register(RegistrationRequestModel request)
    {
        try
        {
            service.RegisterUser(request);
            return Results.Ok();
        }
        catch (UsernameAlreadyExistsException e)
        {
            return Results.BadRequest(e.Message);
        }
    }
    
    [AllowAnonymous]
    [HttpPost("refresh")]
    public IResult Refresh(RefreshRequestModel request)
    {
        try
        {
            return Results.Ok(service.Refresh(request));
        }
        catch (SecurityTokenException e)
        {
            return Results.BadRequest(e.Message);
        }
        catch
        {
            return Results.Unauthorized();
        }
    }
    
}