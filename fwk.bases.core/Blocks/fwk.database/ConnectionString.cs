using System;
using System.Collections.Generic;
using System.Text;

namespace Fwk.Database
{

    public class cnnStrings : List<cnnString>
    {

    }
    public class cnnString
    {
        public string name { get; set; }
        public string databaseName { get; set; }
        public string serverName { get; set; }
        public string userName { get; set; }

        public bool windowsAutentification { get; set; }
    }




    public class ConnectionStrings : List<ConnectionString>
    {

    }

    public class ConnectionString
    {
        public string name { get; set; }
        public string cnnString { get; set; }
    }

}
