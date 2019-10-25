namespace  Fwk.Security.Identity
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;


    public partial class SecurityRule
    {
        //[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2214:DoNotCallOverridableMethodsInConstructors")]
        public SecurityRule()
        {
            SecurityRolesInRules = new HashSet<SecurityRolesInRules>();
            SecurityRulesInCategory = new HashSet<SecurityRulesInCategory>();
        }
        [Key]
        public Guid Id { get; set; }

 
        [StringLength(50)]
        public string Description { get; set; }

        [Required]
        [StringLength(50)]
        public string Name { get; set; }

        //[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public  ICollection<SecurityRolesInRules> SecurityRolesInRules { get; set; }

        //[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Usage", "CA2227:CollectionPropertiesShouldBeReadOnly")]
        public  ICollection<SecurityRulesInCategory> SecurityRulesInCategory { get; set; }
    }

  
}
