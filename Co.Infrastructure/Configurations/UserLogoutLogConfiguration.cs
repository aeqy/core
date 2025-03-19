using Co.Domain.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Co.Infrastructure.Configurations;

public class UserLogoutLogConfiguration : IEntityTypeConfiguration<UserLogoutLog>
{
    public void Configure(EntityTypeBuilder<UserLogoutLog> builder)
    {
        builder.ToTable("UserLogoutLogs");
        builder.HasKey(e => e.Id);
        builder.Property(e => e.UserId).IsRequired();
        builder.Property(e => e.LogoutTime).IsRequired();
        builder.Property(e => e.LogoutType).IsRequired().HasMaxLength(50);
        builder.Property(e => e.InitiatedBy).IsRequired().HasMaxLength(100);
        builder.Property(e => e.ClientIp).HasMaxLength(50);
        builder.Property(e => e.UserAgent).HasMaxLength(500);
    }
}