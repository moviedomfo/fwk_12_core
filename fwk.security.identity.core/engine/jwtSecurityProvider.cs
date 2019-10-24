using Fwk.Exceptions;
using Fwk.HelperFunctions;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Fwk.Security.Identity
{

    /// <summary>
    /// en asp net core este valor debe ser seteado luego de ser inicializado en Startup
    /// var serverSettings = new secConfig();
    ///   Configuration.Bind("secConfig", secConfig);      
    ///   services.AddSingleton(secConfig);
    ///  
    /// El json secConfig debe ser incluida en appsettings.json en raiz.-
    ///  {
    ///   "Logging": {
    ///     "LogLevel": {
    ///         "Microsoft": "Information"
    ///             }
    ///     },
    ///    "secConfig":[
    ///             {..}, 
    ///             {..}
    ///         ]  
    ///   }
    /// </summary>
    public class helper
    {
        

        static void intialize(string settingName)
        {
            //if (secConfig != null) return;

            ////"secConfig.json"
            //string settingName = System.Configuration.ConfigurationManager.AppSettings["secConfig"];
            ////"secConfig.json";//string.Format("apiConfig.{0}.json", env);

            //if (settingName == null)
            //{
            //    throw new TechnicalException("No se encontro configurada la appSetting secConfig ");
            //}
            //if (!System.IO.File.Exists(settingName))
            //{
            //    throw new TechnicalException("No se encontro el archivo " + settingName);
            //}

            //string apiConfigString = FileFunctions.OpenTextFile(settingName);


            //try
            //{
            //    secConfig = (secConfig)SerializationFunctions.DeSerializeObjectFromJson(typeof(secConfig), apiConfigString);
            //}
            //catch (Exception)
            //{
            //    throw new TechnicalException("El archivo " + settingName + "No tiene un formato correcto");
            //}

        }
        
        public static IdentityResult Get_errorIdentityResult(string errorMessage) {

            var result = new IdentityResult();
            var err = new IdentityError();
            err.Description = errorMessage;

            result.Errors.ToList().Add(err);

            return result;
        }
        public static string GetHash(string input)
        {
            HashAlgorithm hashAlgorithm = new SHA256CryptoServiceProvider();

            byte[] byteValue = System.Text.Encoding.UTF8.GetBytes(input);

            byte[] byteHash = hashAlgorithm.ComputeHash(byteValue);

            return Convert.ToBase64String(byteHash);
        }



        /// <summary>
        /// 
        /// </summary>
        /// <param name="userData"></param>
        /// <returns></returns>
        internal static string CustomGeneratePasswordResetToken(String userData)
        {
            byte[] time = BitConverter.GetBytes(DateTime.UtcNow.ToBinary());
            byte[] key = Encoding.ASCII.GetBytes(userData);
            string token = Convert.ToBase64String(time.Concat(key).ToArray());

            return token;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="userData"></param>
        /// <param name="token"></param>
        /// <param name="expirationTime"></param>
        /// <param name="expirationFormat"></param>
        /// <returns></returns>
        internal Boolean CustomValidateToken(String userData, String token, Int32 expirationTime, ExpirationFormat expirationFormat)
        {
            byte[] data = Convert.FromBase64String(token);
            DateTime time = DateTime.FromBinary(BitConverter.ToInt64(data, 0));
            String tokenUserData = BitConverter.ToString(data, 8);
            DateTime dt = DateTime.UtcNow;
            switch (expirationFormat)
            {
                case ExpirationFormat.MINUTES:
                    {
                        dt = dt.AddMinutes(-expirationTime);
                        break;
                    }
                case ExpirationFormat.DAY:
                    {
                        dt = dt.AddMinutes(-expirationTime);
                        break;
                    }
                case ExpirationFormat.SECONDS:
                    {
                        dt = dt.AddSeconds(-expirationTime);
                        break;
                    }
                case ExpirationFormat.HOURS:
                    {
                        dt = dt.AddHours(-expirationTime);
                        break;
                    }
            }
            return (time < DateTime.UtcNow.AddMinutes(-expirationTime) || tokenUserData.CompareTo(userData) != 0);

        }
        public enum ExpirationFormat
        {
            DAY,
            MINUTES,
            SECONDS,
            HOURS
        }
    }

    /// <summary>
    /// En asp net core este valor debe ser seteado luego de ser inicializado en Startup
    /// var serverSettings = new secConfig();
    ///   Configuration.Bind("fwk_securityProviders", secConfig);      
    ///   services.AddSingleton(secConfig);
    ///  
    /// El json secConfig debe ser incluido en appsettings.json en raiz.-
    ///  {
    ///   "Logging": {
    ///     "LogLevel": {
    ///         "Microsoft": "Information"
    ///             }
    ///     },
    ///    "fwk_securityProviders":[
    ///                 {..}, 
    ///                 {..}
    ///              ]  
    ///   }
    /// </summary>
    public class secConfig
    {
        public List<jwtSecurityProvider> fwk_securityProviders { get; set; }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="providerName"></param>
        /// <returns></returns>
        public jwtSecurityProvider GetByName(string providerName)
        {


            if (this.fwk_securityProviders == null)
            {
                throw new TechnicalException("No se encontro configurada la appSetting secConfig ");
            }

            jwtSecurityProvider prov = null;

            if (string.IsNullOrEmpty(providerName))
                prov = this.fwk_securityProviders.First();
            else
                prov = this.fwk_securityProviders.Where(p => p.name.Equals(providerName)).FirstOrDefault();

            if (prov==null)
            {
                throw new TechnicalException("No se encontro proveedor de seguridad configurado con el nombre " + providerName);
            }


            return prov;

        }

        /// <summary>
        /// retorna el nombre de una cadena de conexion configurada .-
        /// </summary>
        /// <param name="providerName"></param>
        /// <returns></returns>
        public string GetcnnstringName(string providerName)
        {
            TechnicalException te = null;
            var prov = GetByName(providerName);
            if (prov == null)
            {

                if (string.IsNullOrEmpty(providerName))
                    te = new TechnicalException("Fwk.Security.Identity error : No se puede obtener el proveedor de seguridad por defecto");
                else
                    te = new TechnicalException("Fwk.Security.Identity error : No se puede obtener el proveedor de seguridad " + providerName);

                //ExceptionHelper.SetTechnicalException<SecurityManager>(te);
                te.ErrorId = "4500";
                throw te;
            }

            if (string.IsNullOrEmpty(prov.securityModelContext))
            {
                te = new TechnicalException("Fwk.Security.Identity error : el proveedor " + providerName + " no tiene un nombre de cadena de conexión configurada");

                //ExceptionHelper.SetTechnicalException<SecurityManager>(te);
                te.ErrorId = "4501";
                throw te;
            }
            return prov.securityModelContext;
        }
    }
    /// <summary>
    /// Define un objeto con las configuraciones requeridas por el standar JWT
    /// </summary>
    public class jwtSecurityProvider
    {
        /// <summary>
        /// Nombre dek proveedor de seguridad 
        /// </summary>
        public string name { get; set; }

        /// <summary>
        /// Nombre del Resourse Server : Puede ser del dispatcher que ejecuta los servicios .-
        /// </summary>
        public string audienceId { get; set; }
        /// <summary>
        /// Nombre que identifica el Authorization Server en el que se confia 
        /// </summary>
        public string issuer { get; set; }

        /// <summary>
        /// Texto symmetricKeyAsBase64 
        /// </summary>
        public string audienceSecret { get; set; }

        /// <summary>
        /// Nombre de cadena de conección donde se encuentra el contexto de seguridad de Security Mannager.-
        /// si no se utiliza el modelo de seguridad propuesto por Fwk.Security.Identity no es necesaria esta configuracion
        /// </summary>
        public string securityModelContext { get; set; }

        /// <summary>
        /// TTL del token en segundos
        /// </summary>
        public int expires { get; set; }

    }
}
