using Microsoft.AspNetCore.Identity;

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;


namespace Fwk.Security.Identity
{
  
    public partial class SecurityUser :IdentityUser<Guid>
    {
        //[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public SecurityUser():base()
        {
            SecuritytUserLogins = new HashSet<SecuritytUserLogin>();
            SecurityUserClaims = new HashSet<SecurityUserClaim>();
            SecurityRoles = new HashSet<SecurityRole>();
        }

        public Guid Id { get; set; }

        [StringLength(256)]
        public string Email { get; set; }

        public bool EmailConfirmed { get; set; }

        public string PasswordHash { get; set; }

        public string SecurityStamp { get; set; }

        public string PhoneNumber { get; set; }

        public bool PhoneNumberConfirmed { get; set; }

        public bool TwoFactorEnabled { get; set; }

        public DateTime? LockoutEndDateUtc { get; set; }

        public bool LockoutEnabled { get; set; }

        public int AccessFailedCount { get; set; }


        public DateTime CreatedDate { get; set; }
        public DateTime LastLogInDate { get; set; }

        [Required]
        [StringLength(256)]
        public string UserName { get; set; }

        //[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SecuritytUserLogin> SecuritytUserLogins { get; set; }

        //[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SecurityUserClaim> SecurityUserClaims { get; set; }

        //[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public virtual ICollection<SecurityRole> SecurityRoles { get; set; }



        public List<String> GetRolesArray()
        {
            List<String> roles = new List<String>();
            if (this.SecurityRoles != null)
            {
                if (this.SecurityRoles.Count != 0)
                {
                    roles = new List<String>();
                    SecurityRoles.ToList().ForEach(r =>
                    {
                        roles.Add(r.Name);
                    });
                }
            }
           
            return roles;
        }
    }
}
