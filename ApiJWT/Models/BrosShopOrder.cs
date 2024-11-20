using System;
using System.Collections.Generic;

namespace ApiJWT.Models;

public partial class BrosShopOrder
{
    public int BrosShopOrderId { get; set; }

    public int BrosShopUserId { get; set; }

    public DateTime BrosShopDateTimeOrder { get; set; }

    public string? BrosShopTypeOrder { get; set; }

    public virtual ICollection<BrosShopOrderComposition> BrosShopOrderCompositions { get; set; } = new List<BrosShopOrderComposition>();

    public virtual BrosShopUser BrosShopUser { get; set; } = null!;
}
