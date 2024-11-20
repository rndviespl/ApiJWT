namespace ApiJWT.Models
{
    public partial class AccountController
    {
        public class RefreshRequest
        {
            public string AccessToken { get; set; }
            public string RefreshToken { get; set; }
        }
    }
}