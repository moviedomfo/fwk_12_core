using Fwk.Bases;
using System;
using System.Collections.Generic;
using System.Text;

namespace Fwk.Bases.ISVC
{
    public class DispatcherInfoBE : Entity
    {
        public DispatcherInfoBE()
        {
            //Cnnstrings = new CnnstringBEList();
        }
        /// <summary>
        /// Lista de cadenas de conección
        /// </summary>
        //public CnnstringBEList Cnnstrings { get; set; }
        public String WindowsServiceName { get; set; }
        public DateTime ServiceDate { get; set; }
        /// <summary>
        /// Cadena de coneccion que posee el dispatcher para obtener su entorno de configuracion. 
        /// spesifica donde esta registrada la instancia del dispatcher
        /// </summary>
        public string ServiceDispatcherConnection { get; set; }

        /// <summary>
        /// Nombre de instancia del dispatcher
        /// </summary>
        public string ServiceDispatcherName { get; set; }

        /// <summary>
        /// Ip donde esta correindo el servicio
        /// </summary>
        public string MachineIp { get; set; }

        /// <summary>
        /// Service Metadata Providers  configurados
        /// </summary>
        //public List<Fwk.ConfigSection.MetadataProvider> MetadataProviders { get; set; }

}
    }

    //public class CnnstringBEList : Entities<CnnstringBE> { }

    //public class CnnstringBE : Entity
    //{
    //    public CnnstringBE()
    //    { }
    //    public CnnstringBE(ConnectionStringSettings cnn)
    //    {
    //        Name = cnn.Name;
    //        ConnectionString = cnn.ConnectionString;
    //    }


    //    public String Name { get; set; }
    //    public String ConnectionString { get; set; }
    //}
//}
