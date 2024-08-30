using Microsoft.EntityFrameworkCore;
using MessageApi.Models;

namespace MessageApi.Data
{
    public class MessageContext : DbContext
    {
        public MessageContext(DbContextOptions<MessageContext> options) : base(options) { }

        public DbSet<Message> Messages { get; set; }
    }
}