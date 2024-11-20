namespace ApiJWT.Models
{
    public class BrosShopCategory
    {
        public int BrosShopCategoryId { get; set; }

        public string BrosShopCategoryTitle { get; set; } = null!;

        public virtual ICollection<BrosShopProduct> BrosShopProducts { get; set; } = new List<BrosShopProduct>();
    }
}