using Serilog;
using Serilog.Context;
using System.Diagnostics;

namespace AuthLicensingApi.Middleware;

public class CorrelationIdMiddleware
{
    private readonly RequestDelegate _next;

    public CorrelationIdMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext ctx)
    {
        // Generate or reuse correlation ID
        var cid = ctx.Request.Headers["X-Correlation-ID"].FirstOrDefault() ?? Guid.NewGuid().ToString("n");
        ctx.Items["cid"] = cid;

        // Try to get username from JWT (if any)
        var username = ctx.User?.Identity?.IsAuthenticated == true
            ? ctx.User.Identity!.Name ?? "(token)"
            : "(anonymous)";

        var endpoint = ctx.Request.Path.Value ?? "(unknown)";

        // Start timer
        var sw = Stopwatch.StartNew();

        // Push context so every Log.Information includes these fields
        using (LogContext.PushProperty("cid", cid))
        using (LogContext.PushProperty("user", username))
        using (LogContext.PushProperty("endpoint", endpoint))
        {
            await _next.Invoke(ctx);
            sw.Stop();

            // Log the request summary after it completes
            Log.Information("HTTP {Method} {Endpoint} => {StatusCode} ({Elapsed} ms)",
                ctx.Request.Method,
                endpoint,
                ctx.Response.StatusCode,
                sw.ElapsedMilliseconds);
        }
    }
}
