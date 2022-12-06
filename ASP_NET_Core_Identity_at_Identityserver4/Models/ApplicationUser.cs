using Microsoft.AspNetCore.Identity;

namespace ASP_NET_Core_Identity_at_Identityserver4.Models
{
    /// <summary>
    /// Додайте дані профілю для користувачів програми, додавши властивості до класу ApplicationUser
    /// </summary>
    /// <remarks>
    /// Наслідує <see cref="IdentityUser"/> в якому є інформація про <paramref name="Id"/> у вигляді <see cref="System.Guid.NewGuid()"/> користувача його <paramref name="UserName"/>
    /// </remarks>
    public class ApplicationUser : IdentityUser
    {
        /// <summary>
        /// Поле яке буде містити опис користувача
        /// </summary>
        /// <remarks>
        /// default: "Пустий опис користувача"
        /// </remarks>
        public string Description { get; set; } = "Пустий опис користувача";
    }
}
