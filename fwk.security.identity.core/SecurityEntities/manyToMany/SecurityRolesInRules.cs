namespace Fwk.Security.Identity
{
    using System;

    public class SecurityRolesInRules
    {
        public Guid RolId { get; set; }

        public Guid RuleId { get; set; }

        public SecurityRole SecurityRole { get; set; }
        public SecurityRule SecurityRule { get; set; }
    }
}
