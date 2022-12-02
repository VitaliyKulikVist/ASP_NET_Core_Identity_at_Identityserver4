namespace ASP_NET_Core_Identity_at_Identityserver4
{
    public static class IdentityConstants
    {
        /// <summary>
        /// Імя для доступу до даних 1-го рівня
        /// </summary>
        /// <remarks>
        /// scope1
        /// </remarks>
        public static string ApiScope_Level1 { get; } = "Доступ Першого рівня";

        /// <summary>
        /// Імя для доступу до даних 2-го рівня
        /// </summary>
        /// <remarks>
        /// scope2
        /// </remarks>
        public static string ApiScope_Level2 { get; } = "Доступ Другого рівня";
    }
}
