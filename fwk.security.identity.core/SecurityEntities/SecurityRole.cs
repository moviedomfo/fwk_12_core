namespace Fwk.Security.Identity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;

    public partial class SecurityRole//: IdentityRole<Guid>
    {
        public SecurityRole():base()
        {
            SecurityRolesInRules = new HashSet<SecurityRolesInRules>();
            SecurityUserRoles = new HashSet<SecurityUserRoles>();
        }
        

        [Key]
        public Guid Id { get; set; }

        public string Description { get; set; }

        [Required]
        [StringLength(256)]
        public string Name { get; set; }
        
        public virtual ICollection<SecurityRolesInRules> SecurityRolesInRules { get; set; }

        public virtual ICollection<SecurityUserRoles> SecurityUserRoles { get; set; }


    }


}
