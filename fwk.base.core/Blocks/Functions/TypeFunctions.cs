using System;
using System.Data;

using System.IO;

using Fwk.Bases;
using System.Collections.Generic;
using System.Reflection;
using System.Text;
//using System.Runtime.Serialization.Formatters.Binary;

namespace Fwk.HelperFunctions
{
	/// <summary>
	/// Funciones de Tipos.
	/// </summary>
	/// <Date>13-05-2009</Date>
	/// <Author>Marcelo F. Oviedo</Author>
    public class TypeFunctions
    {
        /// <summary> 
        /// Valida si el valor pasado por parametro es un entero.-
        /// </summary>
        /// <param name="pValue">Texto a evaluar.-</param>
        /// <returns></returns>
        public static bool IsInteger(string pValue)
        {
            try
            {
                Convert.ToInt32(pValue);
                return true;
            }
            catch
            {
                return false;
            }
        }

     

        /// <summary>
        /// Se valida si la entrada de datos contiene solo Letras
        /// </summary>
        /// <param name="pInput"></param>
        /// <returns></returns>
        public static bool IsAlpha(string pInput)
        {
            string wLetters = "abcdefghijklmñnopqrstuvwxyzüáéíóú";
            pInput = pInput.Trim();

            string wCaracter = String.Empty;

            for (int i = 0; i < pInput.Length; i++)
            {
                wCaracter = pInput.Substring(i, 1);
                wCaracter = wCaracter.ToLower();

                if (wLetters.IndexOf(wCaracter) < 0)
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Se valida si la entrada de datos contiene solo Letras y números
        /// </summary>
        /// <param name="pInput"></param>
        /// <returns></returns>
        public static bool IsAlphaNumeric(string pInput)
        {
            string wLetters = "abcdefghijklmñnopqrstuvwxyzüáéíóú1234567890";
            pInput = pInput.Trim();

            string wCaracter = String.Empty;

            for (int i = 0; i < pInput.Length; i++)
            {
                wCaracter = pInput.Substring(i, 1);
                wCaracter = wCaracter.ToLower();

                if (wLetters.IndexOf(wCaracter) < 0)
                {
                    return false;
                }
            }
            return true;
        }

        /// <summary>
        /// Verifica si existen caracteres no validos.
        /// en una cadena de texto.
        /// </summary>
        /// <param name="pValue">Texto a evaluar.</param>
        /// <returns>True: si existen caracteres invalidos.</returns>
        /// <Date>12-07-2009</Date>
        /// <Author>Marcelo Oviedo</Author>
        public static bool WrongCharacters(string pValue)
        {
            string wCaracteres = "%";
            string wCharacter;
            int wComparation;

            for (int i = 0; i < pValue.Length; i++)
            {
                wCharacter = pValue.Substring(i, 1);
                wComparation = wCaracteres.IndexOf(wCharacter);

                if (wComparation > -1) return false;
            }
            return true;
        }

   

     


        

        /// <summary>
        /// Convierte un tipo de SQLServer a un System.SqlDbType
        /// </summary>
        /// <param name="Value">Tipo de SQLServer </param>
        /// <returns>SqlDbType</returns>
        /// <author>Marcelo F. Oviedo</author>
        public static SqlDbType ConvertSQLToDbSql(string Value)
        {
            SqlDbType oType = new SqlDbType();

            switch (Value.ToUpper())
            {
                case "NCHAR":
                    oType = SqlDbType.NChar;
                    break;
                case "VARCHAR":
                    oType = SqlDbType.VarChar;
                    break;
                case "NVARCHAR":
                    oType = SqlDbType.NVarChar;
                    break;
                case "INT":
                    oType = SqlDbType.Int;
                    break;
                case "BIGINT":
                    oType = SqlDbType.BigInt;
                    break;
                case "SMALLBIGINT":
                    oType = SqlDbType.SmallInt;
                    break;
                case "BIT":
                    oType = SqlDbType.Bit;
                    break;
                case "DATETIME":
                    oType = SqlDbType.DateTime;
                    break;
                case "SMALLDATETIME":
                    oType = SqlDbType.SmallDateTime;
                    break;
                case "FLOAT":
                    oType = SqlDbType.Float;
                    break;
                case "MONEY":
                    oType = SqlDbType.Money;
                    break;
                case "SMALLMONEY":
                    oType = SqlDbType.SmallMoney;
                    break;
                case "DECIMAL":
                    oType = SqlDbType.Decimal;
                    break;
                case "TEXT":
                    oType = SqlDbType.Text;
                    break;
                case "NTEXT":
                    oType = SqlDbType.NText;
                    break;
                case "IMAGE":
                    oType = SqlDbType.Image;
                    break;
                case "VARBINARY":
                    oType = SqlDbType.VarBinary;
                    break;
                case "BINARY":
                    oType = SqlDbType.Binary;
                    break;
            }
            return oType;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="Value"></param>
        /// <returns></returns>
        public static string ConvertSqlToCSahrp(string Value)
        {
            string wTipo = String.Empty;
            switch (Value.ToUpper())
            {
                case "VARCHAR":
                case "NVARCHAR":
                    wTipo = "string";
                    break;
                case "INT":
                    wTipo = "int";
                    break;
                case "BIT":
                    wTipo = "bool";
                    break;
                case "DATETIME":
                case "SMALLDATETIME":
                    wTipo = "System.DateTime";
                    break;

            }

            return wTipo;

        }

        /// <summary>
        /// Convierte una  array of 8-bit a su equivalente  System.String,
        ///  codificado en base 64 digitos
        /// </summary>
        /// <returns></returns>
        public static string ConvertBytesToBase64String(Byte[] byteArray)
        {
            return Convert.ToBase64String(byteArray);
        }

        /// <summary>
        /// Convierte un Byte[] a un System.Drawing.Image -
        /// </summary>
        /// <param name="byteArray">Byte[] que tiene formato de imagen</param>
        /// <returns>Image</returns>
        /// <author>Marcelo F. Oviedo</author>
        //public static Image ConvertByteArrayToImage(byte[] byteArray)
        //{
        //    if (byteArray == null)
        //        return null;
        //    Image returnImage = null;
        //    using (MemoryStream ms = new MemoryStream(byteArray))
        //    {
        //        returnImage = Image.FromStream(ms);
        //        return returnImage;
        //    }
        //}


        /// <summary>
        /// Convierte un System.Drawing.Image a Byte[]
        /// </summary>
        /// <param name="imageToConvert">Imagen</param>
        /// <param name="formatOfImage">Formato ej:System.Drawing.Imaging.ImageFormat.Gif</param>
        /// <returns>byte[]</returns>
        /// <author>Marcelo F. Oviedo</author>
        //public static byte[] ConvertImageToByteArray(System.Drawing.Image imageToConvert,
        //    ImageFormat formatOfImage)
        //{
        //    using (MemoryStream ms = new MemoryStream())
        //    {
        //        imageToConvert.Save(ms, formatOfImage);
        //        return ms.ToArray();
        //    }
        //}

        /// <summary>
        /// Utiliza ASCIIEncoding
        /// </summary>
        /// <param name="stringText"></param>
        /// <returns></returns>
        public static byte[] ConvertStringToByteArray(string stringText)
          
        {
            System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
            return encoding.GetBytes(stringText);
        }

        /// <summary>
        ///  Utiliza ASCIIEncoding
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static string ConvertBytesToTextString(Byte[] bytes)
        {

            System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
            return encoding.GetString(bytes);
            
        }
        /// <summary>
        /// Convierte una secuencia de bytes (cualquier clase que herede de stream) a un string .-
        /// </summary>
        /// <param name="pStream">cualquier clase que herede de stream</param>
        /// <returns>string del binario</returns>
        /// <author>Marcelo F. Oviedo</author>
        public static string ConvertToBase64String(Stream pStream)
        {

            Byte[] arr = new Byte[pStream.Length];
            pStream.Read(arr, 0, Convert.ToInt32(pStream.Length));
            pStream.Dispose();
            return Convert.ToBase64String(arr);
        }
        /// <summary>
        /// Obtiene el string que reprecenta el Base64 del archivo.-
        /// </summary>
        /// <param name="pFullFileName">Nombre del archivo del cual se quiere obtener el Base64</param>
        /// <returns>string del binario en Base64</returns>
        /// <author>Marcelo F. Oviedo</author>
        public static string ConvertToBase64String(String pFullFileName)
        {
            FileStream fs = new FileStream(pFullFileName, FileMode.Open, FileAccess.Read);
            return ConvertToBase64String(fs);
        }

        /// <summary>
        /// Convierte un Base64 string en un array de bytes. 
        /// </summary>
        /// <param name="pBase64String">String con el Base64 del binario</param>
        /// <returns>Byte[]</returns>
        /// <author>Marcelo F. Oviedo</author>
        public static Byte[] ConvertFromBase64String(String pBase64String)
        {
            Byte[] arrWrite = Convert.FromBase64String(pBase64String);
            return arrWrite;
        }


        /// <summary>
        /// Convierte un Base64 string a un archivo binario.-
        /// </summary>
        /// <param name="pBase64String">String con el Base64 del binario</param>
        /// <param name="pFullFileName">Nombre del archivo</param>
        /// <returns>Byte array que reprecenta el archivo</returns>
        /// <author>Marcelo F. Oviedo</author>
        public static Byte[] ConvertFromBase64StringToFile(String pBase64String, String pFullFileName)
        {
            FileStream fw = new FileStream(pFullFileName, FileMode.Create, FileAccess.Write);
            Byte[] arrWrite = Convert.FromBase64String(pBase64String);
            fw.Write(arrWrite, 0, arrWrite.Length);
            fw.Dispose();
            return arrWrite;
        }

     


        /// <summary>
        /// Toma los elementos de pEntitiCollection y los agrega a la coleccion TEntities
        /// </summary>
        /// <typeparam name="TEntities">Tipo de la coleccion de entidades</typeparam>
        /// <typeparam name="TEntity">Tipo TEntity</typeparam>
        /// <param name="pEntitiCollection">Coleccion de entidades</param>
        /// <param name="pIenumerableList">Clase de lin q con los elementos TEntity</param>
        public static void SetEntitiesFromIenumerable<TEntities, TEntity>(TEntities pEntitiCollection, IEnumerable<TEntity> pIenumerableList)
            where TEntities : Entities<TEntity>
            where TEntity : Entity
        {
            foreach (TEntity item in pIenumerableList)
            {
                pEntitiCollection.Add(item);
            }
        }
       
        /// <summary>
        /// Funcion que busca recurcivamente si Tsource hereda de Tbase
        /// </summary>
        /// <param name="Tsource">Tipo origen </param>
        /// <param name="Tbase">Tipo base del cual puede heredar el tipo origen</param>
        /// <returns></returns>
        public static bool TypeInheritFrom(Type Tsource, Type Tbase)
        {

            throw new NotImplementedException();
            //if (Tsource.BaseType == null) return false;
            //if (Tsource.BaseType != Tbase)
            //    return TypeInheritFrom(Tsource.BaseType, Tbase);
            //else
            //    return true;
        }
      
       
        /// <summary>
        /// Give a string representation of a object, with use of reflection.
        /// </summary>
        /// <param name="o">O.</param>
        /// <returns></returns>
        public static string ToString(Object o)
        {
            StringBuilder sb = new StringBuilder();
            Type t = o.GetType();

            var pi = t.GetRuntimeProperties();

            sb.Append(string.Concat("Properties for: " , o.GetType().Name , System.Environment.NewLine));
            foreach (PropertyInfo i in pi)
            {
                if (!(i.Name.CompareTo("CanUndo") == 0 ||
                    i.Name.CompareTo("CanRedo") == 0))
                {
                    try
                    {

                        sb.Append(string.Concat("\t" , i.Name , "(" , i.PropertyType.ToString() , "): "));
                        if (null != i.GetValue(o, null))
                        {
                            sb.Append(i.GetValue(o, null).ToString());
                        }

                    }
                    catch
                    {
                    }
                    sb.Append(System.Environment.NewLine);
                }
            }

            var fi = t.GetRuntimeFields();

            foreach (FieldInfo i in fi)
            {
                try
                {
                    sb.Append(string.Concat("\t" , i.Name , "(" , i.FieldType.ToString() , "): "));
                    if (null != i.GetValue(o))
                    {
                        sb.Append(i.GetValue(o).ToString());
                    }

                }
                catch
                {
                }
                sb.Append(System.Environment.NewLine);

            }

            return sb.ToString();
        }
    }
}
