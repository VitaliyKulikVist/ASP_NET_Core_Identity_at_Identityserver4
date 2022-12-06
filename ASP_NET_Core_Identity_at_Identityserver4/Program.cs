using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.SystemConsole.Themes;
using System;
using System.Linq;

namespace ASP_NET_Core_Identity_at_Identityserver4
{
    /// <summary>
    /// Головний клас 
    /// </summary>
    public class Program
    {
        /// <summary>
        /// Головний метод застосунку, з якого починається робота програми
        /// </summary>
        /// <param name="args">Параметри які можуть вплинути на роботу застосунку в ході запуску</param>
        /// <returns></returns>
        public static int Main(string[] args)
        {
            AddAndConfiguredLogger();

            try
            {
                var seed = args.Contains("/seed");
                if (seed)
                {
                    args = args.Except(new[] { "/seed" }).ToArray();
                }

                var host = CreateHostBuilder(args).Build();

                if (seed)
                {
                    SeedingDataAtBD(host);

                    return 0;
                }

                Log.Information("Початок роботи Хоста...");
                host.Run();

                return 0;
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Host terminated unexpectedly.");
                return 1;
            }
            finally
            {
                Log.CloseAndFlush();
            }
        }

        /// <summary>
        /// Метод необхідний для налаштування Логування даних в проекті, і формат логів при виводі в консоль
        /// </summary>
        private static void AddAndConfiguredLogger()
        {
            AnsiConsoleTheme theme = AnsiConsoleTheme.Code;

            Log.Logger = new LoggerConfiguration()
                .MinimumLevel.Debug()
                .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                //.MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
                .MinimumLevel.Override("System", LogEventLevel.Warning)
                .MinimumLevel.Override("Microsoft.AspNetCore.Authentication", LogEventLevel.Information)
                .Enrich.FromLogContext()

                .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}", theme: theme)
                .CreateLogger();
        }

        /// <summary>
        /// Метод в якому відбувається заповнення бази данних початковими даними
        /// </summary>
        /// <param name="host">Параметрт необхідний для витягування сервісу <see cref="IConfiguration"/></param>
        private static void SeedingDataAtBD(IHost host)
        {
            var timeStart = DateTime.UtcNow;
            Log.Information("Заповнення бази данних...\t{timeStart}", timeStart);
            var config = host.Services.GetRequiredService<IConfiguration>();
            var connectionString = config.GetConnectionString("DefaultConnection");
            SeedData.EnsureSeedData(connectionString);
            var timeFinish = DateTime.UtcNow;
            Log.Information("База данних заповнена.\t{timeFinish}", timeFinish);
        }

        /// <summary>
        /// Метод в якому відбувається створення конфігурування <see cref="IHostBuilder"/> 
        /// </summary>
        /// <param name="args">Вхідні параметри аргументів в яких можна додати додаткові налаштування для конфігурування
        /// які будуть використовуватись при запуску застосунку</param>
        /// <returns>Буде повернуто зконфігурований <see cref="IHostBuilder"/></returns>
        private static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .UseSerilog()
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.UseStartup<Startup>();
                });
    }
}