using System.ComponentModel.DataAnnotations;

namespace JWT.RequestModels;

public class RegistrationRequestModel
{
    [Required]
    [MaxLength(50)]
    public string Username { get; set; } = null!;
    
    [Required]
    public string Password { get; set; } = null!;
}