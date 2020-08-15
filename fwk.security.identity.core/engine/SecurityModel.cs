using System;

using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using Fwk.Security.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Fwk.Security.Identity
{

    /// <summary>
    /// https://www.youtube.com/watch?v=fnd23XZVjBk
    /// https://www.youtube.com/watch?v=D06nNkfJK8w
    /// </summary>
    public class SecurityModelContext : DbContext
    {
        string connectionString;
        public SecurityModelContext(string connectionString)
        {

            this.connectionString = connectionString;
        }
  

        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            base.OnConfiguring(optionsBuilder);
            //Usa SQL server
            optionsBuilder.UseSqlServer(connectionString, options => { });

        }
        public virtual DbSet<SecurityClient> SecurityClients { get; set; }
        public virtual DbSet<SecurityRefreshToken> SecurityRefreshTokens { get; set; }
        public virtual DbSet<SecurityRole> SecurityRoles { get; set; }
        public virtual DbSet<SecurityRule> SecurityRules { get; set; }
        public virtual DbSet<SecurityRulesCategory> SecurityRulesCategories { get; set; }
        public virtual DbSet<SecuritytUserLogin> SecuritytUserLogins { get; set; }
        public virtual DbSet<SecurityUserClaim> SecurityUserClaims { get; set; }
        public virtual DbSet<SecurityUser> SecurityUsers { get; set; }
        public virtual DbSet<SecurityUserRoles> SecurityUserRoles { get; set; }
        public virtual DbSet<SecurityRolesInRules> SecurityRolesInRules { get; set; }
        public virtual DbSet<SecurityRulesInCategory> SecurityRulesInCategory { get; set; }


        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            //modelBuilder.Entity<SecurityRole>()
            //    .HasMany(e => e.SecurityRules)
            //    .WithMany(e => e.SecurityRoles)
            //    .Map(m => m.ToTable("SecurityRolesInRules").MapLeftKey("RolId").MapRightKey("RuleId"));

            //modelBuilder.Entity<SecurityRole>()
            //    .HasMany(e => e.SecurityUsers)
            //    .WithMany(e => e.SecurityRoles)
            //    .Map(m => m.ToTable("SecurityUserRoles").MapLeftKey("RoleId").MapRightKey("UserId"));

            //modelBuilder.Entity<SecurityRule>()
            //    .HasMany(e => e.SecurityRulesCategories)
            //    .WithMany(e => e.SecurityRules)
            //    .Map(m => m.ToTable("SecurityRulesInCategory").MapLeftKey("RuleId").MapRightKey("CategoryId"));

            //modelBuilder.Entity<SecurityUser>()
            //    .HasMany(e => e.SecuritytUserLogins)
            //    .WithRequired(e => e.SecurityUser)
            //    .HasForeignKey(e => e.UserId);

            //modelBuilder.Entity<SecurityUser>()
            //    .HasMany(e => e.SecurityUserClaims)
            //    .WithRequired(e => e.SecurityUser)
            //    .HasForeignKey(e => e.UserId);
        }

        /// <summary>
        /// Configure the one-to-many relationship using Fluent API 
        /// </summary>
        /// <param name="modelBuilder"></param>
        //protected override void OnModelCreating(ModelBuilder modelBuilder)
        //{

        //    #region SecurityUserRoles many to many
        //    modelBuilder.Entity<SecurityUserRoles>().HasKey(sc => new { sc.RolId, sc.UserId });

        //    modelBuilder.Entity<SecurityUserRoles>()
        //        .HasOne<SecurityRole>(sc => sc.SecurityRole)
        //        .WithMany(s => s.SecurityUserRoles)
        //        .HasForeignKey(sc => sc.RolId);

        //    modelBuilder.Entity<SecurityUserRoles>()
        //        .HasOne<SecurityUser>(sc => sc.SecurityUser)
        //        .WithMany(s => s.SecurityUserRoles)
        //        .HasForeignKey(sc => sc.UserId);


        //    modelBuilder.Entity<SecurityRolesInRules>().HasKey(sc => new { sc.RolId, sc.RuleId });
        //    //.Map(m => m.ToTable("SecurityRolesInRules").MapLeftKey("RolId").MapRightKey("RuleId"));

        //    modelBuilder.Entity<SecurityRolesInRules>()
        //        .HasOne<SecurityRole>(sc => sc.SecurityRole)
        //        .WithMany(s => s.SecurityRolesInRules)
        //        .HasForeignKey(sc => sc.RolId);

        //    modelBuilder.Entity<SecurityRolesInRules>()
        //        .HasOne<SecurityRule>(sc => sc.SecurityRule)
        //        .WithMany(s => s.SecurityRolesInRules)
        //        .HasForeignKey(sc => sc.RuleId);



        //    modelBuilder.Entity<SecurityRulesInCategory>().HasKey(sc => new { sc.CategoryId, sc.RuleId });

        //    modelBuilder.Entity<SecurityRulesInCategory>()
        //         .HasOne<SecurityRulesCategory>(sc => sc.SecurityRulesCategory)
        //        .WithMany(s => s.SecurityRulesInCategory)
        //        .HasForeignKey(sc => sc.CategoryId);

        //    modelBuilder.Entity<SecurityRulesInCategory>()
        //       .HasOne<SecurityRule>(sc => sc.SecurityRule)
        //        .WithMany(s => s.SecurityRulesInCategory)
        //        .HasForeignKey(sc => sc.RuleId);



        //    #endregion
        //    modelBuilder.Entity<SecurityUserClaim>()
        //        .HasOne<SecurityUser>(e => e.SecurityUser)
        //        .WithMany(e => e.SecurityUserClaims)
        //        .HasForeignKey(e => e.UserId);



        //    modelBuilder.Entity<SecuritytUserLogin>().HasKey(sc => new { sc.LoginProvider, sc.ProviderKey, sc.UserId });

        //    modelBuilder.Entity<SecuritytUserLogin>()
        //    .HasOne<SecurityUser>(e => e.SecurityUser)
        //    .WithMany(e => e.SecuritytUserLogins)
        //    .HasForeignKey(e => e.UserId);

        //}
    }
}


    
