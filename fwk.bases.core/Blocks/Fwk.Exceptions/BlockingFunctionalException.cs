using System;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;

namespace Fwk.Exceptions
{
	/// <summary>
	/// Summary description for BlockingFunctionalException.
	/// </summary>
	[ComVisible(false)]
	//[Serializable()]
	public class BlockingFunctionalException : FunctionalException
	{
     

		#region Contructores

        /// <summary>
        /// 
        /// </summary>
        /// <param name="pMessage"></param>
		public BlockingFunctionalException(string pMessage) : base(null,"CustomMessage_Error", new string[] {pMessage})
		{
		}

      
        /// <summary>
        /// 
        /// </summary>
        /// <param name="pMsgId"></param>
        /// <param name="pParams"></param>
		public BlockingFunctionalException(string pMsgId, params string[] pParams) : this(pMsgId, null, pParams)
		{
		}
        /// <summary>
        /// 
        /// </summary>
        /// <param name="pMsgId"></param>
        /// <param name="pInner"></param>
        /// <param name="pParams"></param>
		public BlockingFunctionalException(string pMsgId, Exception pInner, params string[] pParams) : base(null,pMsgId, pInner, pParams)
		{
		}

     

		#endregion

		
	}
}