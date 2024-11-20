namespace ApiJWT.Models
{
    public class BrosShopOrder
    {
        public int BrosShopOrderId { get; set; }

        public int BrosShopUserId { get; set; }

        public DateTime BrosShopDateTimeOrder { get; set; }

        public string? BrosShopTypeOrder { get; set; }

        public virtual BrosShopUser BrosShopUser { get; set; } = null!;
    }
}