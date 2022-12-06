using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace IdentityServerHost.Quickstart.UI
{
    /// <summary>
    /// Клас кастомного атрибуту [<paramref name="SecurityHeaders"/>] який в даному випадку із за наслідування класу <see cref="ActionFilterAttribute"/> можна вішати лише на контролени які відправляють запити і отримують відповіді
    /// </summary>
    /// <remarks>
    /// Клас наслідує фільтр дії(Action) <see cref="ActionFilterAttribute"/>
    /// <para>
    /// в класі перевизначений метод <paramref name="OnResultExecuting"/> 
    /// </para>
    /// </remarks>
    public class SecurityHeadersAttribute : ActionFilterAttribute
    {
        /// <summary>
        /// Цей метод викликається перед виконанням результату дії контролера, але результат вже отриманий(іншими словами певна валідація результату)
        /// </summary>
        /// <remarks>
        /// В цьому методі до відповіді (Response) якщо єснують в відповіді певні ключі, тоді буде доданий новий запис в (Response)
        /// </remarks>
        /// <param name="context">Сюди автоматично буде передано рузультат запиту або іншими словами вміст результату запиту</param>
        public override void OnResultExecuting(ResultExecutingContext context)
        {
            var result = context.Result;
            if (result is ViewResult)
            {
                /* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
                HTTP-заголовок відповіді X-Content-Type-Options — це маркер, який використовується сервером для вказівки на те, що типи MIME, рекламовані в заголовках Content-Type, повинні дотримуватися та не змінюватися. Заголовок дозволяє уникнути перехоплення типу MIME, кажучи, що типи MIME налаштовано навмисно.
                */
                if (!context.HttpContext.Response.Headers.ContainsKey("X-Content-Type-Options"))
                {
                    context.HttpContext.Response.Headers.Add("X-Content-Type-Options", "nosniff");///Блокує запит, якщо призначення запиту має стиль типу, а тип MIME не є text/css, або має тип script, а тип MIME не є типом <seealso cref="MIME JavaScript"> https://html.spec.whatwg.org/multipage/infrastructure.html#javascript-mime-type</seealso>  
                }

                /* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
                Заголовок HTTP-відповіді X-Frame-Options можна використовувати, щоб вказати, чи має веб-переглядач дозволити відображати сторінку у <frame>, <iframe>, <embed> або <object>. Сайти можуть використовувати це, щоб уникнути атак зловмисників, переконавшись, що їх вміст не вбудовано в інші сайти.
                */
                if (!context.HttpContext.Response.Headers.ContainsKey("X-Frame-Options"))
                {
                    context.HttpContext.Response.Headers.Add("X-Frame-Options", "SAMEORIGIN");//Сторінку можна відобразити, лише якщо всі вихідні кадри мають те саме походження, що й сама сторінка.
                }

                // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
                var csp = "default-src 'self'; object-src 'none'; frame-ancestors 'none'; sandbox allow-forms allow-same-origin allow-scripts; base-uri 'self';";

                // також подумайте про додавання upgrade-insecure-requests, коли у вас буде HTTPS для виробництва
                // csp += "upgrade-insecure-requests;";
                // також приклад, якщо вам потрібно, щоб зображення клієнтів відображалися наприклад з twitter
                // csp += "img-src 'self' https://pbs.twimg.com;";

                /* один раз для браузерів, сумісних зі стандартами
                Заголовок відповіді HTTP Content-Security-Policy дозволяє адміністраторам веб-сайту контролювати ресурси, які агент користувача може завантажувати для певної сторінки. За кількома винятками, політики здебільшого передбачають визначення джерел серверів і кінцевих точок сценаріїв. Це допомагає захиститися від атак міжсайтових сценаріїв (Cross-site_scripting).
                */
                if (!context.HttpContext.Response.Headers.ContainsKey("Content-Security-Policy"))
                {
                    context.HttpContext.Response.Headers.Add("Content-Security-Policy", csp);
                }

                /* Політика безпеки вмісту (CSP)
                    * — це додатковий рівень безпеки, який допомагає виявляти та пом’якшувати певні типи атак, зокрема міжсайтові сценарії (XSS) і атаки з впровадженням даних. Ці атаки використовуються для всього: від крадіжки даних до псування сайтів і розповсюдження шкідливого програмного забезпечення.
                */
                if (!context.HttpContext.Response.Headers.ContainsKey("X-Content-Security-Policy"))
                {
                    context.HttpContext.Response.Headers.Add("X-Content-Security-Policy", csp);
                }

                /* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy
                HTTP-заголовок Referrer-Policy контролює, скільки інформації про реферера
                (надісланої разом із заголовком Referer)
                слід включити до запитів. Окрім заголовка HTTP, цю політику можна встановити в HTML
                */
                var referrer_policy = "no-referrer"; //Заголовок Referer буде пропущено: надіслані запити не містять жодної інформації про реферера.

                /* exemples referrer_policy
                var referrer_policy = "no-referrer-when-downgrade"; //Надсилайте джерело, шлях і рядок запиту в Referer, коли рівень безпеки протоколу залишається незмінним або покращується (HTTP→HTTP, HTTP→HTTPS, HTTPS→HTTPS). Не надсилайте заголовок Referer для запитів у менш безпечні місця призначення (HTTPS→HTTP, HTTPS→файл).

                 var referrer_policy = "origin"; //Надішліть лише джерело в заголовку Referer. Наприклад, документ за адресою https://example.com/page.html надішле реферер https://example.com/.

                 var referrer_policy = "origin-when-cross-origin"; //Під час виконання запиту того самого джерела до того самого рівня протоколу (HTTP→HTTP, HTTPS→HTTPS), надішліть джерело, шлях і рядок запиту. Надсилайте лише джерело для запитів перехресних джерел і запитів до менш безпечних місць призначення (HTTPS→HTTP).

                 var referrer_policy = "same-origin"; //Надсилайте джерело, шлях і рядок запиту для запитів із однаковим джерелом. Не надсилайте заголовок Referer для запитів між джерелами

                 var referrer_policy = "strict-origin"; //Надсилати лише джерело, коли рівень безпеки протоколу залишається незмінним (HTTPS→HTTPS). Не надсилайте заголовок Referer у менш безпечні місця призначення (HTTPS→HTTP).

                 var referrer_policy = "strict-origin-when-cross-origi"; //(default)//  //Надсилайте джерело, шлях і рядок запиту під час виконання запиту того самого джерела. Для перехресних запитів надсилайте джерело (тільки), коли рівень безпеки протоколу залишається незмінним (HTTPS→HTTPS). Не надсилайте заголовок Referer у менш безпечні місця призначення (HTTPS→HTTP).
                */

                if (!context.HttpContext.Response.Headers.ContainsKey("Referrer-Policy"))
                {
                    context.HttpContext.Response.Headers.Add("Referrer-Policy", referrer_policy);
                }
            }
        }
    }
}
