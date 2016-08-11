namespace Fwk.Bases
{
    /// <summary>
    /// 
    /// </summary>
    public interface IClientServiceBase 
    {

        
        /// <summary>
        /// 
        /// </summary>
        IBaseEntity EntityResult
        {
            get;
            set;
        }

        /// <summary>
        /// 
        /// </summary>
        IBaseEntity EntityParam
        {
            get;
            set;
        }
        
    }
}
