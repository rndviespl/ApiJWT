namespace ApiJWT.Models
{
    public partial class AccountController
    {
        public class LoginResponse
        {
            public string AccessToken { get; set; }
            public DateTimeOffset AccessTokenExpiration { get; set; }
            public string RefreshToken { get; set; }
        }
    }
}