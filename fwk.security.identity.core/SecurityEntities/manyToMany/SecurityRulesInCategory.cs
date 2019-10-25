namespace Fwk.Security.Identity
{
    using System;

    public  class SecurityRulesInCategory
    {
       
        
        public Guid CategoryId { get; set; }
        public SecurityRulesCategory SecurityRulesCategory { get; set; }

        public Guid RuleId { get; set; }

        public SecurityRule SecurityRule { get; set; }

    }
}
