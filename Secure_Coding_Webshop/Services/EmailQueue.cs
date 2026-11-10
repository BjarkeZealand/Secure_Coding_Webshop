using Secure_Coding_Webshop.Models;
using Secure_Coding_Webshop.Services.Interfaces;
using System.Threading.Channels;

namespace Secure_Coding_Webshop.Services
{
    public sealed class EmailQueue : IEmailQueue
    {
        // Begrænset kø: hvis den er fuld, droppes mails i stedet for at æde hukommelse (DoS)
        private readonly Channel<EmailMessage> _channel = Channel.CreateBounded<EmailMessage>(
            new BoundedChannelOptions(1000) { FullMode = BoundedChannelFullMode.Wait });

        public bool TryEnqueue(EmailMessage message) => _channel.Writer.TryWrite(message);
        public ChannelReader<EmailMessage> Reader => _channel.Reader;
    }
}
