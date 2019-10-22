﻿using System;
using System.Collections.Generic;
using System.Linq;

using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Fwk.Security;
using Fwk.Security.Common;
using Fwk.Security.Identity;
using Microsoft.AspNetCore.Identity;

namespace Fwk.Security.Identity
{
    public class SecurityManager
    {

        static Guid emptyGuid = new Guid("00000000-0000-0000-0000-000000000000");
        static SecurityManager()
        {

        }







        #region Security Users 
        public static ClaimsIdentity GenerateClaimsIdentity(SecurityUser user, string sec_provider = "")
        {
            // Note the authenticationType must match the one 
            // defined in CookieAuthenticationOptions.AuthenticationType
            //var userIdentity =     await manager.CreateIdentityAsync(this,   DefaultAuthenticationTypes.ApplicationCookie);
            // Add custom user claims here

            //ClaimsIdentity claimsIdentity = new ClaimsIdentity(DefaultAuthenticationTypes.ApplicationCookie);
            //claimsIdentity.AddClaim(new Claim("userName", "newValue"));

            ClaimsIdentity oAuthIdentity = new ClaimsIdentity("ExternalBearer");
            oAuthIdentity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));
            if (!String.IsNullOrEmpty(user.Email))
                oAuthIdentity.AddClaim(new Claim(ClaimTypes.Email, user.Email));
            user.SecurityRoles.ToList().ForEach(r =>
            {
                oAuthIdentity.AddClaim(new Claim("role", r.Name));
            });


            return oAuthIdentity;
        }



        internal static SecurityRoleBEList Roles_get_byUserNAme(string username, string sec_provider)
        {
            SecurityRoleBEList list = new SecurityRoleBEList();
            SecurityRoleBE r = new SecurityRoleBE();

            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var user = db.SecurityUsers.Where(item => item.UserName.Equals(username)).FirstOrDefault();

                    user.SecurityRoles.ToList().ForEach(rol =>
                    {
                        r = new SecurityRoleBE();
                        r.Id = rol.Id;
                        r.Name = rol.Name;
                        r.Description = rol.Description;
                        list.Add(r);
                    });


                }
                return list;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        internal static void User_RemoveRoles(Guid id, string sec_provider = "")
        {
            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var user = db.SecurityUsers.Where(item => item.Id == id).FirstOrDefault();

                    user.SecurityRoles.ToList().ForEach(rol =>
                    {
                        user.SecurityRoles.Remove(rol);
                        db.SaveChanges();
                    });


                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        internal static void User_Update(SecurityUser usersBE, string userName, string sec_provider = "")
        {
            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var user = db.SecurityUsers.Where(item => item.UserName.ToLower() == userName.ToLower()).FirstOrDefault();
                    usersBE.UserName = user.UserName;
                    usersBE.Email = user.Email;
                    usersBE.PhoneNumber = user.PhoneNumber;
                    //usersBE.UserName = user.UserName;
                    //var rol = user.SecurityRoles.Where(r => r.Name.ToLower() == rolName.ToLower()).FirstOrDefault();
                    //if (rol != null)
                    //{
                    //    user.SecurityRoles.Remove(rol);
                    //    db.SaveChanges();
                    //}
                    db.SaveChanges();
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        internal static void User_RemoveFromRole(string userName, string rolName, string sec_provider = "")
        {
            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var user = db.SecurityUsers.Where(item => item.UserName.ToLower() == userName.ToLower()).FirstOrDefault();

                    var rol = user.SecurityRoles.Where(r => r.Name.ToLower() == rolName.ToLower()).FirstOrDefault();
                    if (rol != null)
                    {
                        user.SecurityRoles.Remove(rol);
                        db.SaveChanges();
                    }

                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public static async Task<IdentityResult> User_CreateAsync(SecurityUser user, string password, string sec_provider = "")
        {
            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    user.PasswordHash = helper.GetHash(password);
                    if (user.Id == null || user.Id.Equals(emptyGuid))
                        user.Id = Guid.NewGuid();
                    db.SecurityUsers.Add(user);
                    var res = await db.SaveChangesAsync();
                    return IdentityResult.Success;

                }
            }
            catch (Exception ex)
            {
                return helper.Get_errorIdentityResult( Fwk.Exceptions.ExceptionHelper.GetAllMessageException(ex) );
            }
        }
        public static IdentityResult User_Create(SecurityUser user, string password, bool asignRoles = false, string sec_provider = "")
        {
            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    user.PasswordHash = helper.GetHash(password);
                    if (user.Id == null || user.Id.Equals(emptyGuid))
                        user.Id = Guid.NewGuid();
                    if (asignRoles == false)
                    {
                        user.SecurityRoles = null;
                    }
                    db.SecurityUsers.Add(user);
                    var res = db.SaveChanges();
                    return IdentityResult.Success;

                }
            }
            catch (Exception ex)
            {


                return helper.Get_errorIdentityResult( Fwk.Exceptions.ExceptionHelper.GetAllMessageException(ex) );
            }
        }
        internal static bool User_Exist(string userName, string sec_provider = "")
        {
            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var u = db.SecurityUsers.Where(p => p.UserName.Equals(userName.TrimEnd(), StringComparison.OrdinalIgnoreCase)).FirstOrDefault();
                    if (u != null)
                    {
                        string name = u.UserName;
                    }
                    return db.SecurityUsers.Any(p => p.UserName.ToLower() == userName.ToLower());

                }
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public static void User_Aprove(string userName, string sec_provider = "")
        {
            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var user = db.SecurityUsers.Where(p => p.UserName.ToLower() == userName.ToLower()).FirstOrDefault();
                    user.EmailConfirmed = true;
                    //var user2 = UserFindByName(userName);

                    db.SaveChanges();
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }

        }

        public static void User_Dislook(string userName, string sec_provider = "")
        {
            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var user = db.SecurityUsers.Where(p => p.UserName.ToLower() == userName.ToLower()).FirstOrDefault();
                    user.LockoutEnabled = false;
                    user.LockoutEndDateUtc = null;

                    db.SaveChangesAsync();
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }

        }


        public static void User_Lockout(string userName, DateTime lockoutEndDate, string sec_provider = "")
        {
            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var user = db.SecurityUsers.Where(p => p.UserName.ToLower() == userName.ToLower()).FirstOrDefault();
                    user.LockoutEnabled = true;
                    user.LockoutEndDateUtc = lockoutEndDate;

                    db.SaveChangesAsync();
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }

        }

        public static LoginResult User_CheckStatus(string userName, string sec_provider)
        {
            LoginResult result = new LoginResult();
            try
            {
                var user = User_FindByName(userName, false, sec_provider);

                if (user != null)
                {
                    if (user.LockoutEnabled)
                    {
                        result.Status = SecuritySignInStatus.LockedOut.ToString();
                        result.Message = "Usuario bloqueado";
                    }
                    if (user.EmailConfirmed == false)
                    {
                        result.Status = SecuritySignInStatus.RequiresVerification.ToString();
                        result.Message = "Usuario Require verificaciión";
                    }
                }
                else
                {
                    result.Status = SecuritySignInStatus.Failure.ToString();
                    result.Message = "Usuario no existe";
                }

            }
            catch (Exception ex)
            {
                result.Status = SecuritySignInStatus.Failure.ToString();
                result.Message = Fwk.Exceptions.ExceptionHelper.GetAllMessageException(ex);

            }
            return result;
        }

        private async Task<bool> GetLockoutEnabled(SecurityUser user)
        {
            var isLockoutEnabled = user.LockoutEnabled;

            if (isLockoutEnabled == false) return false;

            var shouldRemoveLockout = DateTime.Now >= user.LockoutEndDateUtc;

            if (shouldRemoveLockout)
            {
                User_Dislook(user.UserName);
                //await _userLockoutStore.ResetAccessFailedCountAsync(user);

                //await _userLockoutStore.SetLockoutEnabledAsync(user, false);

                return false;
            }

            return true;
        }

        internal static SecurityUserBE GetUsrBE(SecurityUser user)
        {
            SecurityUserBE userBe = new SecurityUserBE();
            userBe.AccessFailedCount = user.AccessFailedCount;
            userBe.Email = user.Email;
            userBe.Id = user.Id;
            userBe.EmailConfirmed = user.EmailConfirmed;
            userBe.UserName = user.UserName;
            userBe.TwoFactorEnabled = user.TwoFactorEnabled;

            if (user.SecurityRoles.Count != 0)
            {

                userBe.Roles = new List<String>();
                user.SecurityRoles.ToList().ForEach(r =>
                {
                    userBe.Roles.Add(r.Name);
                });
            }
            return userBe;
        }

        public static SecurityUser User_FindByName(string userName, bool includeRoles = false, string sec_provider = "")
        {
            try
            {

                ICollection<SecurityRole> r;
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var user = db.SecurityUsers.Where(p => p.UserName.ToLower() == userName.ToLower()).FirstOrDefault();
                    if (user != null && includeRoles)
                    {
                        //al consultarlo se incluye la busqueda
                        r = user.SecurityRoles;
                    }
                    return user;

                }
            }
            catch (Exception ex)
            {
                throw ex;
            }

        }
        public static List<SecurityUser> User_getAll(string sec_provider)
        {

            //ICollection<SecurityRole> r;
            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    return db.SecurityUsers.ToList();
                    //if (includeRoles)
                    //{
                    //    //al consultarlo se incluye la busqueda
                    //    r = user.SecurityRoles;
                    //}
                    //return user; 

                }
            }
            catch (Exception ex)
            {
                throw ex;
            }

        }
        public static SecurityUser User_FindById(Guid usderId, bool includeRoles = false, string sec_provider = "")
        {
            ICollection<SecurityRole> r;
            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var user = db.SecurityUsers.Where(p => p.Id == usderId).FirstOrDefault();
                    if (includeRoles)
                    {
                        //al consultarlo se incluye la busqueda
                        r = user.SecurityRoles;
                    }
                    return user; ;

                }
            }
            catch (Exception ex)
            {
                throw ex;
            }

        }

        public static IdentityResult User_AsignRoles(AssignRolesToUserModel model, string sec_provider)
        {

            IdentityResult result = null;


            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {

                    var userFromBD = db.SecurityUsers.Where(p => p.UserName.ToLower() == model.userName.ToLower()).FirstOrDefault();
                    if (userFromBD != null)
                    {

                        foreach (string rolName in model.roles)
                        {

                            var rol = db.SecurityRoles.Where(p => p.Name == rolName).FirstOrDefault();
                            if (rol == null)
                            {

                                result = helper.Get_errorIdentityResult(String.Format("El rol {0} no existe .- ", rolName));
                                break;
                            }

                            userFromBD.SecurityRoles.Add(rol);

                        }

                        db.SaveChanges();


                        result = IdentityResult.Success;

                    }
                    else
                    {
                        result = helper.Get_errorIdentityResult("Usuario no existe .- ");
                    }
                }
            }
            catch (Exception ex)
            {
                result =helper.Get_errorIdentityResult( Fwk.Exceptions.ExceptionHelper.GetAllMessageException(ex) );

            }
            return result;
        }

        public static Task<IdentityResult> User_RemoveLoginAsync(Guid userId, UserLoginInfo userLoginInfo)
        {
            throw new NotImplementedException();
        }

        public static Task<IdentityResult> User_RemovePasswordAsync(Guid userId, string sec_provider)
        {
            throw new NotImplementedException();
        }

        public async static Task<IdentityResult> User_AddLoginAsync(Guid userId, UserLoginInfo userLoginInfo, string sec_provider)
        {
            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var user = User_FindById(userId);

                    SecuritytUserLogin securitytUserLogin = new SecuritytUserLogin();

                    securitytUserLogin.LoginProvider = userLoginInfo.LoginProvider;
                    securitytUserLogin.ProviderKey = userLoginInfo.ProviderKey;
                    securitytUserLogin.UserId = userId;
                    db.SecuritytUserLogins.Add(securitytUserLogin);

                    var res = await db.SaveChangesAsync();
                    return IdentityResult.Success;

                }
            }
            catch (Exception ex)
            {
                return helper.Get_errorIdentityResult( Fwk.Exceptions.ExceptionHelper.GetAllMessageException(ex));
            }
        }

        public static LoginResult User_Authenticate(string userName, string password, string sec_provider)
        {
            LoginResult result = new LoginResult();


            var user = User_FindByName(userName, true, sec_provider);


            if (user != null)
            {
                if (user.LockoutEnabled)
                {
                    result.Status = SecuritySignInStatus.LockedOut.ToString();
                    result.Message = "Usuario bloqueado";
                    return result;
                }
                if (user.EmailConfirmed == false)
                {
                    result.Status = SecuritySignInStatus.RequiresVerification.ToString();
                    result.Message = "Usuario require verificaciión";
                    return result;
                }

                bool isValid = VerifyHashedPassword(password, user.PasswordHash);

                if (!isValid)
                {
                    result.Status = SecuritySignInStatus.Failure.ToString();
                    result.Message = "Password es incorrecto";

                }
                else
                {
                    result.Status = SecuritySignInStatus.Success.ToString();
                    result.User = user;
                    result.User.PasswordHash = "";
                    var roles = result.User.SecurityRoles.Count;


                }

            }
            else
            {
                result.Status = SecuritySignInStatus.Failure.ToString();
                result.Message = "Usuario no existe";
            }

            return result;
        }


        public static bool VerifyHashedPassword(string password, string storedHash)
        {
            var hash = helper.GetHash(password);
            return hash == storedHash;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="userName"></param>
        /// <param name="newPassword"></param>
        /// <returns></returns>
        public static IdentityResult User_RessetPassword(string userName, string newPassword, string sec_provider)
        {
            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {

                    var user = db.SecurityUsers.Where(p => p.UserName.ToLower() == userName.ToLower()).FirstOrDefault();
                    user.PasswordHash = helper.GetHash(newPassword);

                    var res = db.SaveChanges();
                    return IdentityResult.Success;

                }
            }
            catch (Exception ex)
            {
                return helper.Get_errorIdentityResult( Fwk.Exceptions.ExceptionHelper.GetAllMessageException(ex) );
            }
        }

        public static IdentityResult User_ChangePassword(string userName, string oldPassword, string newPassword, string sec_provider)
        {

            var result = User_Authenticate(userName, oldPassword, sec_provider);
            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {

                    var user = db.SecurityUsers.Where(p => p.UserName.ToLower() == userName.ToLower()).FirstOrDefault();
                    user.PasswordHash = helper.GetHash(newPassword);

                    var res = db.SaveChanges();
                    return IdentityResult.Success;

                }
            }
            catch (Exception ex)
            {
                return helper.Get_errorIdentityResult( Fwk.Exceptions.ExceptionHelper.GetAllMessageException(ex) );
            }


        }


        #endregion

        #region -- roles -- 
        public static SecurityRole Role_FindById(Guid roleId, bool includeRules = false, bool includeUsers = false, string sec_provider = "")
        {
            ICollection<SecurityRule> r;
            ICollection<SecurityUser> u;
            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var role = db.SecurityRoles.Where(p => p.Id == roleId).FirstOrDefault();
                    if (includeRules)
                    {
                        //al consultarlo se incluye la busqueda
                        r = role.SecurityRules;
                    }
                    if (includeUsers)
                    {
                        //al consultarlo se incluye la busqueda
                        u = role.SecurityUsers;
                    }
                    return role;

                }
            }
            catch (Exception ex)
            {
                throw ex;
            }

        }


        public static SecurityRole Role_FindByName(String roleName, bool includeRules = false, bool includeUsers = false, string sec_provider = "")
        {
            ICollection<SecurityRule> r;
            ICollection<SecurityUser> u;
            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var role = db.SecurityRoles.Where(p => p.Name.ToLower() == roleName.ToLower()).FirstOrDefault();
                    if (includeRules)
                    {
                        //al consultarlo se incluye la busqueda
                        r = role.SecurityRules;
                    }
                    if (includeUsers)
                    {
                        //al consultarlo se incluye la busqueda
                        u = role.SecurityUsers;
                    }
                    return role;

                }
            }
            catch (Exception ex)
            {
                throw ex;
            }

        }
        public static SecurityRoleBEList Role_getAll(string sec_provider)
        {
            SecurityRoleBEList listBE = new SecurityRoleBEList();
            SecurityRoleBE be = new SecurityRoleBE();
            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var list = db.SecurityRoles;
                    list.ToList().ForEach(rc =>
                    {
                        be = new SecurityRoleBE();

                        be.Id = rc.Id;
                        be.Name = rc.Name;
                        be.Description = rc.Description;
                        listBE.Add(be);
                    });
                    return listBE;



                }

            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        public static IdentityResult Role_AsignRules(AssignRulesToRoleModel model, string sec_provider)
        {

            IdentityResult result = null;


            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var role = db.SecurityRoles.Where(p => p.Name == model.roleName).FirstOrDefault();


                    if (role != null)
                    {

                        foreach (string ruleName in model.rules)
                        {

                            var rule = db.SecurityRules.Where(p => p.Name == ruleName).FirstOrDefault();
                            if (rule == null)
                            {
                                result =helper.Get_errorIdentityResult( String.Format("La regla {0} no existe .- ", ruleName) );
                                break;
                            }

                            role.SecurityRules.Add(rule);

                        }

                        db.SaveChanges();


                        result = IdentityResult.Success;
                    }

                    else
                    {

                        result =helper.Get_errorIdentityResult( "Rol no existe .- " );
                    }
                }
            }
            catch (Exception ex)
            {
                result =helper.Get_errorIdentityResult( ex.Message);

            }
            return result;
        }

        public static Task<IdentityResult> UserAddLoginAsync(Guid id, UserLoginInfo login)
        {
            throw new NotImplementedException();
        }

        public static void Role_Create(SecurityRole rol, string sec_provider)
        {
            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var exist = db.SecurityRoles.Any(p => p.Name == rol.Name);
                    if (exist)
                    {
                        throw new Exception(String.Format("El rol {0} existe .- ", rol.Name));
                    }
                    if (rol.Id == null || rol.Id.Equals(emptyGuid))
                        rol.Id = Guid.NewGuid();
                    db.SecurityRoles.Add(rol);
                    db.SaveChanges();



                }

            }
            catch (Exception ex)
            {
                throw ex;
            }

        }
        #endregion


        #region -- rules -- 

        public static SecurityRuleBEList Rule_getAll(string sec_provider)
        {
            SecurityRuleBEList listBE = new SecurityRuleBEList();
            SecurityRuleBE be = new SecurityRuleBE();
            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var list = db.SecurityRules;
                    list.ToList().ForEach(rc =>
                    {
                        be = new SecurityRuleBE();

                        be.Id = rc.Id;
                        be.Name = rc.Name;
                        be.Description = rc.Description;
                        listBE.Add(be);
                    });
                    return listBE;



                }

            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        internal static bool Rule_check(string ruleName, string userName, string sec_provider)
        {

            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var user = User_FindByName(userName, true);

                    var securityRule = db.SecurityRules.Where(item => item.Name.ToLower() == ruleName.ToLower()).FirstOrDefault();
                    if (securityRule != null && user == null)
                    {
                        var roles = securityRule.SecurityRoles;
                        var insersect = user.SecurityRoles.Intersect(securityRule.SecurityRoles);

                        return insersect.Count() != 0;
                    }



                }
                return false;
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        public static SecurityRule Rule_getByName(string name, string sec_provider)
        {
            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var rule = db.SecurityRules.Where(p => p.Name == name).FirstOrDefault();
                    if (rule == null)
                    {
                        throw new Exception(String.Format("La regla {0} existe .- ", name));
                    }
                    return rule;



                }

            }
            catch (Exception ex)
            {
                throw ex;
            }

        }
        static Guid emptyGuid = new Guid("00000000-0000-0000-0000-000000000000");
        public static void Rule_Create(SecurityRule rule, string sec_provider)
        {
            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var exist = db.SecurityRules.Any(p => p.Name == rule.Name);
                    if (exist)
                    {
                        throw new Exception(String.Format("La regla {0} existe .- ", rule.Name));
                    }

                    if (rule.Id == null || rule.Id.Equals(emptyGuid))
                        rule.Id = Guid.NewGuid();
                    db.SecurityRules.Add(rule);
                    db.SaveChanges();

                }

            }
            catch (Exception ex)
            {
                throw ex;
            }

        }

        internal static void Rule_Update(SecurityRuleBE rule, string sec_provider)
        {
            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var ruleDB = db.SecurityRules.Where(p => p.Id == rule.Id).FirstOrDefault();
                    if (ruleDB == null)
                    {
                        throw new Exception(String.Format("La regla {0} existe .- ", rule.Name));
                    }
                    ruleDB.Name = rule.Name;
                    ruleDB.Description = rule.Description;


                    db.SecurityRules.Add(ruleDB);
                    db.SaveChanges();

                }

            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        public static IdentityResult Rule_AsignRoles(AssignRolesToRuleModel model, string sec_provider)
        {

            IdentityResult result = null;


            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var rule = db.SecurityRules.Where(p => p.Name == model.ruleName).FirstOrDefault();


                    if (rule != null)
                    {

                        foreach (string rolName in model.roles)
                        {

                            var rol = db.SecurityRoles.Where(p => p.Name == rolName).FirstOrDefault();
                            if (rol == null)
                            {
                                result =helper.Get_errorIdentityResult( String.Format("La rol {0} no existe .- ", rolName) });
                                break;
                            }

                            rule.SecurityRoles.Add(rol);

                        }

                        db.SaveChanges();


                        result = IdentityResult.Success;
                    }

                    else
                    {

                        result =helper.Get_errorIdentityResult( "Regla no existe .- " });
                    }
                }
            }
            catch (Exception ex)
            {
                result =helper.Get_errorIdentityResult( ex.Message });

            }
            return result;
        }
        #endregion


        #region -- Category -- 
        public static SecurityRulesCategoryBEList RulesCategory_getAll(string sec_provider)
        {
            SecurityRulesCategoryBEList listBE = new SecurityRulesCategoryBEList();
            SecurityRulesCategoryBE be = new SecurityRulesCategoryBE();

            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var list = db.SecurityRulesCategories;
                    list.ToList().ForEach(rc =>
                    {
                        be = new SecurityRulesCategoryBE();

                        be.CategoryId = rc.CategoryId;
                        be.Name = rc.Name;
                        be.ParentCategoryId = rc.ParentCategoryId;
                        listBE.Add(be);
                    });
                    return listBE;



                }

            }
            catch (Exception ex)
            {
                throw ex;
            }
        }
        public static void RuleCategory_Create(SecurityRulesCategory ruleCategory, string sec_provider)
        {
            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var exist = db.SecurityRoles.Any(p => p.Name == ruleCategory.Name);
                    if (exist)
                    {
                        throw new Exception(String.Format("La categoría {0} existe .- ", ruleCategory.Name));
                    }
                    if (ruleCategory.CategoryId == null || ruleCategory.CategoryId.Equals(emptyGuid))
                        ruleCategory.CategoryId = Guid.NewGuid();
                    db.SecurityRulesCategories.Add(ruleCategory);
                    db.SaveChanges();

                }

            }
            catch (Exception ex)
            {
                throw ex;
            }

        }
        public static SecurityRulesCategory Category_getByName(string name, string sec_provider)
        {
            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var item = db.SecurityRulesCategories.Where(p => p.Name == name).FirstOrDefault();
                    if (item == null)
                    {
                        throw new Exception(String.Format("La categoria de regla {0} existe .- ", name));
                    }
                    return item;



                }

            }
            catch (Exception ex)
            {
                throw ex;
            }

        }
        public static void Category_Removee(Guid categoryId, string sec_provider)
        {


            using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
            {
                var category = db.SecurityRulesCategories.Where(p => p.CategoryId == categoryId).FirstOrDefault();
                db.SecurityRulesCategories.Remove(category);
            }
        }
        public static IdentityResult Category_AsignRules(AssignRulesToCategoryModel model, string sec_provider)
        {

            IdentityResult result = null;


            try
            {
                using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
                {
                    var category = db.SecurityRulesCategories.Where(p => p.CategoryId == model.categoryId).FirstOrDefault();


                    if (category != null)
                    {

                        foreach (Guid ruleId in model.rules)
                        {

                            var rule = db.SecurityRules.Where(p => p.Id == ruleId).FirstOrDefault();
                            if (rule == null)
                            {
                                result =helper.Get_errorIdentityResult( String.Format("La regla {0} no existe .- ", ruleId) });
                                break;
                            }

                            category.SecurityRules.Add(rule);

                        }

                        db.SaveChanges();


                        result = IdentityResult.Success;
                    }

                    else
                    {

                        result =helper.Get_errorIdentityResult( "Categoría no existe .- " });
                    }
                }
            }
            catch (Exception ex)
            {
                result =helper.Get_errorIdentityResult( ex.Message });

            }
            return result;
        }
        #endregion


        #region Security Refresh Tokens

        public static SecurityClient ClientFind(string clientId, string sec_provider)
        {
            using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
            {
                var client = db.SecurityClients.Find(clientId);

                return client;

            }

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public static async Task<bool> AddRefreshToken(SecurityRefreshToken token, string sec_provider)
        {
            using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
            {
                var existingToken = db.SecurityRefreshTokens.Where(r => r.Subject == token.Subject && r.ClientId == token.ClientId).FirstOrDefault();
                if (existingToken != null)
                {
                    var result = await RemoveRefreshToken(existingToken, sec_provider);
                }

                db.SecurityRefreshTokens.Add(token);

                return await db.SaveChangesAsync() > 0;
            }



        }

        public static async Task<bool> RemoveRefreshToken(string refreshTokenId, string sec_provider)
        {
            using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
            {
                var refreshToken = await db.SecurityRefreshTokens.FindAsync(refreshTokenId);

                if (refreshToken != null)
                {
                    db.SecurityRefreshTokens.Remove(refreshToken);
                    return await db.SaveChangesAsync() > 0;
                }
            }
            return false;
        }

        public static async Task<bool> RemoveRefreshToken(SecurityRefreshToken refreshToken, string sec_provider)
        {
            using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
            {
                var refreshTokenToRemove = db.SecurityRefreshTokens.Where(p => refreshToken.Id == p.Id).FirstOrDefault();
                db.SecurityRefreshTokens.Remove(refreshTokenToRemove);

                return await db.SaveChangesAsync() > 0;
            }
        }

        public static async Task<SecurityRefreshToken> FindRefreshToken(string refreshTokenId, string sec_provider)
        {
            using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
            {
                var refreshToken = await db.SecurityRefreshTokens.FindAsync(refreshTokenId);

                return refreshToken;
            }
        }

        public static List<SecurityRefreshToken> GetAllRefreshTokens(string sec_provider)
        {
            using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
            {
                return db.SecurityRefreshTokens.ToList();
            }
        }
        public static void ClientCreate(SecurityClient client, string sec_provider)
        {
            using (SecurityModelContext db = new SecurityModelContext(helper.get_secConfig().GetcnnstringName(sec_provider)))
            {
                db.SecurityClients.Add(client); ;
                db.SaveChanges();
            }


        }

        #endregion
    }



    public enum ApplicationTypes
    {
        JavaScript = 0,
        NativeConfidential = 1
    };
}
