namespace JWT.Models;

public class MyUser
{
    public string Login { get; set; } = null!;
    public string Password { get; set; } = null!;
    public string Salt { get; set; } = null!;
    public string RefreshToken { get; set; } = null!;
    public DateTime RefreshTokenExp { get; set; }
}