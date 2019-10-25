namespace Fwk.Security.Identity
{
    using System;

    public  class SecurityUserRoles
    {
       
        
        public Guid UserId { get; set; }
        public SecurityUser SecurityUser { get; set; }

        public Guid RolId { get; set; }

        public SecurityRole SecurityRole { get; set; }

    }
}
