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

        /// <summary>
        /// Імя для доступу до даних для читання
        /// </summary>
        /// <remarks>
        /// Read your data.
        /// </remarks>
        public static string ApiScope_Read { get; } = "read";

        /// <summary>
        /// Імя для доступу до даних для запису
        /// </summary>
        /// <remarks>
        /// Write your data.
        /// </remarks>
        public static string ApiScope_Write { get; } = "write";

        /// <summary>
        /// Імя для доступу до даних для видалення
        /// </summary>
        /// <remarks>
        /// Delete your data.
        /// </remarks>
        public static string ApiScope_Delete { get; } = "delete";
    }
}
