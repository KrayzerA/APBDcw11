namespace JWT.RequestModels;

public class RefreshResponseModel
{
    public string AccessToken { get; set; } = null!;
    public string RefreshToken { get; set; } = null!;
}