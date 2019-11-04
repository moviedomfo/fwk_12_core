//using System;
//using System.Collections.Generic;
//using Fwk.Bases;
//using Fwk.Params.Isvc.CreateParam;
//using Fwk.Params.Back;
//using Fwk.Params.BE;

//namespace Fwk.Params.Svc
//{
//    /// <summary>
//    /// 
//    /// </summary>
//    public class CreateParametroService : BusinessService<CreateParamReq, CreateParamRes>
//    {
//        public override CreateParamRes Execute(CreateParamReq pServiceRequest)
//        {
//            CreateParamRes wRes = new CreateParamRes();

//            ParamDAC.Create(pServiceRequest.BusinessData, new Guid(pServiceRequest.ContextInformation.UserId), pServiceRequest.ContextInformation.AppId);

//            return wRes;
//        }

       
//    }
//}
//namespace Fwk.Params.Isvc.CreateParam
//{
 
//    public class CreateParamReq : Request<ParamBE>
//    {

//        public CreateParamReq()
//        {
//            base.ServiceName = "CreateParamService";
//        }
//    }



    
//    public class CreateParamRes :Response<DummyContract>
//    {
//    }

//}
