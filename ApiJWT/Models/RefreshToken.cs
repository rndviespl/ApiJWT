namespace ApiJWT.Models
{
    public class RefreshToken
    {
        public RefreshToken()
        {
            Id = Guid.NewGuid(); // Генерируем новый GUID при создании объекта
        }

        public Guid Id { get; set; }
        public string Token { get; set; } = null!;
        public DateTime Expiration { get; set; }
        public int BrosShopUserId { get; set; }
        public virtual BrosShopUser BrosShopUser { get; set; } = null!;
    }
}