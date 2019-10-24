namespace Fwk.Security.Identity
{
    using Microsoft.AspNetCore.Identity;
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    
    

    public partial class SecurityRole//: IdentityRole<Guid>
    {
        //[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public SecurityRole():base()
        {
            SecurityRules = new HashSet<SecurityRule>();
            SecurityUsers = new HashSet<SecurityUser>();
        }
        //public SecurityRole(string roleName) : base(roleName)
        //{
        //    SecurityRules = new HashSet<SecurityRule>();
        //    SecurityUsers = new HashSet<SecurityUser>();
        //}


        //public SecurityRole(string roleName,string description) : base(roleName)
        //{
        //    SecurityRules = new HashSet<SecurityRule>();
        //    SecurityUsers = new HashSet<SecurityUser>();

        //    Description = description;
        //}

        [Key]
        public Guid Id { get; set; }

        public string Description { get; set; }

        [Required]
        [StringLength(256)]
        public string Name { get; set; }

        //[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SecurityRule> SecurityRules { get; set; }

        //[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SecurityUser> SecurityUsers { get; set; }


       
    }
}
