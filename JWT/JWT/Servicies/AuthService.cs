using System.IdentityModel.Tokens.Jwt;
using System.Text;
using JWT.Exceptions;
using JWT.Helpers;
using JWT.Models;
using JWT.RequestModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using LoginRequestModel = JWT.Controllers.LoginRequestModel;

namespace JWT.Servicies;

public interface IAuthService
{
    public void RegisterUser(RegistrationRequestModel request);
    public LoginResponseModel LoginUser(LoginRequestModel request);
    public RefreshResponseModel Refresh(RefreshRequestModel request);
}

public class AuthService(IConfiguration configuration) : IAuthService
{
    private static ICollection<MyUser> _users = new List<MyUser>();


    public void RegisterUser(RegistrationRequestModel request)
    {
        if (_users.SingleOrDefault(u => u.Login == request.Username) is not null)
        {
            throw new UsernameAlreadyExistsException($"Username {request.Username} already exists");
        }

        var hashedPasswordAndSalt = MySecurityHelper.GetHashedPasswordAndSalt(request.Password);
        var tokenHandler = new JwtSecurityTokenHandler();
        var refTokenDescription = new SecurityTokenDescriptor
        {
            Issuer = configuration["JWT:RefIssuer"],
            Audience = configuration["JWT:RefAudience"],
            Expires = DateTime.UtcNow.AddDays(1),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:RefKey"]!)),
                SecurityAlgorithms.HmacSha256
            )
        };
        var refToken = tokenHandler.CreateToken(refTokenDescription);
        var newUser = new MyUser
        {
            Login = request.Username,
            Password = hashedPasswordAndSalt.Item1,
            Salt = hashedPasswordAndSalt.Item2,
            RefreshToken = tokenHandler.WriteToken(refToken),
            RefreshTokenExp = refToken.ValidTo
        };

        _users.Add(newUser);
    }

    [AllowAnonymous]
    public LoginResponseModel LoginUser(LoginRequestModel request)
    {
        var user = _users.SingleOrDefault(u => u.Login == request.UserName);
        string hashedPasswordFromDB = user.Password;
        string hashedRequestPassword = MySecurityHelper.GetHashedPasswordWithSalt(request.Password, user.Salt);
        
        if (hashedRequestPassword != hashedPasswordFromDB)
        {
            throw new IncorrectPasswordException("Wrong username or password");
        }

        SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Key"]!));
        SigningCredentials credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        JwtSecurityToken accessToken = new JwtSecurityToken(
            issuer: configuration["JWT:Issuer"],
            audience: configuration["JWT:Audience"],
            expires: DateTime.Now.AddMinutes(15),
            signingCredentials: credentials);
        
        var tokenHandler = new JwtSecurityTokenHandler();
        var refTokenDescription = new SecurityTokenDescriptor
        {
            Issuer = configuration["JWT:RefIssuer"],
            Audience = configuration["JWT:RefAudience"],
            Expires = DateTime.UtcNow.AddDays(1),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:RefKey"]!)),
                SecurityAlgorithms.HmacSha256
            )
        };
        var refToken = tokenHandler.CreateToken(refTokenDescription);
        user.RefreshToken = tokenHandler.WriteToken(refToken);
        user.RefreshTokenExp = refToken.ValidTo;

        return new LoginResponseModel
        {
            AccessToken = new JwtSecurityTokenHandler().WriteToken(accessToken),
            RefreshToken = user.RefreshToken
        };
    }

    [AllowAnonymous]
    [HttpPost("refresh")]
    public RefreshResponseModel Refresh(RefreshRequestModel request)
    {
        var user = _users.SingleOrDefault(u => u.RefreshToken == request.RefreshToken);
        if (user is null)
        {
            throw new SecurityTokenException("Invalid refresh token");
        }

        if (user.RefreshTokenExp < DateTime.Now)
        {
            throw new SecurityTokenException("Refresh token expired");
        }
        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = configuration["JWT:RefIssuer"],
            ValidAudience = configuration["JWT:RefAudience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:RefKey"]!))
        };
        try
        {
            tokenHandler.ValidateToken(request.RefreshToken, tokenValidationParameters, out SecurityToken validatedToken);
            
            SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:Key"]!));
            SigningCredentials credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            JwtSecurityToken accessToken = new JwtSecurityToken(
                issuer: configuration["JWT:Issuer"],
                audience: configuration["JWT:Audience"],
                expires: DateTime.Now.AddMinutes(15),
                signingCredentials: credentials);
            
            var refTokenDescription = new SecurityTokenDescriptor
            {
                Issuer = configuration["JWT:RefIssuer"],
                Audience = configuration["JWT:RefAudience"],
                Expires = DateTime.UtcNow.AddDays(1),
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["JWT:RefKey"]!)),
                    SecurityAlgorithms.HmacSha256
                )
            };
            var refToken = tokenHandler.CreateToken(refTokenDescription);
            
            user.RefreshToken = tokenHandler.WriteToken(refToken);
            user.RefreshTokenExp = refToken.ValidTo;

            return new RefreshResponseModel
            {
                AccessToken = tokenHandler.WriteToken(accessToken),
                RefreshToken = user.RefreshToken
            };
        }
        catch (Exception e)
        {
            throw new SecurityTokenException("Invalid token:" + e);
        }
    }
}