namespace Fwk.Security.Identity
{
    using System;

    /// <summary>
    /// Many to many relationships
    /// </summary>
    public  class SecurityUserRoles
    {
       
        
        public Guid UserId { get; set; }

        public Guid RolId { get; set; }
        public SecurityUser SecurityUser { get; set; }



        public SecurityRole SecurityRole { get; set; }

    }
}
