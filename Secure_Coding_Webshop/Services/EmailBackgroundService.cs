using Secure_Coding_Webshop.Services.Interfaces;

namespace Secure_Coding_Webshop.Services
{
    public sealed class EmailBackgroundService : BackgroundService
    {
        private readonly EmailQueue _queue;
        private readonly IEmailSender _sender;
        private readonly ILogger<EmailBackgroundService> _log;

        public EmailBackgroundService(EmailQueue queue, IEmailSender sender, ILogger<EmailBackgroundService> log)
            => (_queue, _sender, _log) = (queue, sender, log);

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            await foreach (var message in _queue.Reader.ReadAllAsync(stoppingToken))
            {
                try { await _sender.SendAsync(message, stoppingToken); }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _log.LogError(ex, "Kunne ikke sende e-mail");
                }
            }
        }
    }
}
