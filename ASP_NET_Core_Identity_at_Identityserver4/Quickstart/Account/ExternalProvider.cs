namespace IdentityServerHost.Quickstart.UI
{
    /// <summary>
    /// Клас в якому міститься поля які відповідають за відображення для 
    /// додаткових авторизацій будь то фейсбук, гугл тощо...
    /// </summary>
    /// <remarks>
    /// Дана в ці поля назначаються автомамтично в момент коли формується сторінка 
    /// авторизація і в стартапа програми були додані додаткові способи авторизації
    /// </remarks>
    public class ExternalProvider
    {
        public string DisplayName { get; set; }
        public string AuthenticationScheme { get; set; }
    }
}