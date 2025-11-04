using Microsoft.ApplicationInsights.Extensibility;
using Serilog;
using Serilog.Formatting.Compact;

namespace AuthLicensingApi.Extensions;

public static class LoggingExtensions
{
    public static void ConfigureSerilog(string? applicationInsightsConnectionString = null)
    {
        // Ensure logs directory exists
        var logFilePath = Path.Combine(AppContext.BaseDirectory, "logs", "api-.log");
        Directory.CreateDirectory(Path.GetDirectoryName(logFilePath)!);

        // Configure Serilog
        var loggerConfig = new LoggerConfiguration()
            .Enrich.FromLogContext()
            .WriteTo.Console(outputTemplate:
                "[{Timestamp:HH:mm:ss} {Level:u3}] ({cid}) {Message:lj}{NewLine}{Exception}")
            .WriteTo.File(
                new CompactJsonFormatter(),
                logFilePath,
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 14,
                rollOnFileSizeLimit: true,
                fileSizeLimitBytes: 10 * 1024 * 1024
            );

        // Add Application Insights if connection string is provided
        if (!string.IsNullOrWhiteSpace(applicationInsightsConnectionString))
        {
            var telemetryConfig = new TelemetryConfiguration
            {
                ConnectionString = applicationInsightsConnectionString
            };
            loggerConfig.WriteTo.ApplicationInsights(
                telemetryConfig,
                TelemetryConverter.Traces);
        }

        Log.Logger = loggerConfig.CreateLogger();
    }
}
