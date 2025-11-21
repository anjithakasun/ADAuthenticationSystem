using ADAuthentication.PL.Models;
using Microsoft.OpenApi.Services;
using Novell.Directory.Ldap;
using System.Buffers.Text;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices.Protocols;
using System.Reflection;
using System.Reflection.PortableExecutable;

namespace ADAuthentication.PL.Services
{
    public class ActiveDirectoryService
    {
        private readonly string _domain;
        private readonly string _ldapServers;
        private readonly string _ldapPort;
        private readonly string _baseDn;
        private readonly string _lDapPath;

        public ActiveDirectoryService(IConfiguration configuration)
        {
            _ldapServers = configuration["ADCredentials:LdapServers"];
            _domain = configuration["ADCredentials:Domain"];
            //_ldapPort = configuration["ADCredentials:LdapPort"];
            //_baseDn = configuration["ADCredentials:BaseDn"];
            _lDapPath = configuration["ADCredentials:LdapPath"];

            if (string.IsNullOrWhiteSpace(_domain))
                throw new InvalidOperationException("SaltKey is missing or empty in appsettings.json (AppSettings:SaltKey).");
        }
        
        public ApiResponse<ADUserModel> AuthenticateAndGetUser(string username, string password)
        {
            string domainUser = $"{_domain}\\{username}";
            try
            {
                // Convert to string array or list
                string[] ldapServersArray = _ldapServers.Split(',').Select(x => x.Trim()).ToArray();

                // Or as a List<string>
                List<string> ldapServersList = _ldapServers.Split(',').Select(x => x.Trim()).ToList();
                foreach (var ldapServer in ldapServersList)
                {
                    string ldapPath = $"{ldapServer}/{_baseDn}"; // e.g., LDAP://10.100.10.100:389/DC=VFPLC,DC=INT
                                                                 // Use ldapPath in DirectoryEntry
                    using (var entry = new System.DirectoryServices.DirectoryEntry(_lDapPath, domainUser, password))
                    {
                        var nativeObj = entry.NativeObject;

                        // 2. Search AD
                        using (var searcher = new DirectorySearcher(entry))
                        {
                            searcher.Filter = $"(sAMAccountName={username})";

                            searcher.PropertiesToLoad.Add("sAMAccountName");
                            searcher.PropertiesToLoad.Add("givenName");
                            searcher.PropertiesToLoad.Add("sn");
                            searcher.PropertiesToLoad.Add("title");
                            searcher.PropertiesToLoad.Add("department");
                            searcher.PropertiesToLoad.Add("displayName");
                            searcher.PropertiesToLoad.Add("mail");
                            searcher.PropertiesToLoad.Add("physicalDeliveryOfficeName");
                            searcher.PropertiesToLoad.Add("telephoneNumber");

                            var result = searcher.FindOne();
                            if (result == null) return null;

                            ADUserModel modal = new ADUserModel
                            {
                                Username = username,
                                FirstName = GetProp(result, "givenName"),
                                LastName = GetProp(result, "sn"),
                                Department = GetProp(result, "department"),
                                Title = GetProp(result, "title"),
                                DisplayName = GetProp(result, "displayName"),
                                Email = GetProp(result, "mail"),
                                OfficeLocation = GetProp(result, "physicalDeliveryOfficeName"),
                                TelephoneNumber = GetProp(result, "telephoneNumber")
                            };

                            ApiResponse<ADUserModel> uModal = new ApiResponse<ADUserModel>();
                            uModal.Status = true;
                            uModal.Message = "Success Login";
                            uModal.Data = modal;

                            return uModal;
                        }
                    }
                }
                // 1. Authenticate
                return null;
                
            }
            catch(Exception ex)
            {
                ApiResponse<ADUserModel> uModal = new ApiResponse<ADUserModel>();
                uModal.Status = false;
                uModal.Message = "Invalid User Details";
                uModal.Data = null;
                uModal.Exception = ex;
                return uModal;
            }
        }

        private string GetProp(System.DirectoryServices.SearchResult result, string prop)
        {
            return result.Properties.Contains(prop)
                ? result.Properties[prop][0]?.ToString()
                : "";
        }

        public ADUserModel GetUserFromAD(string searchUsername)
        {
            string domainPath = "LDAP://10.100.10.100:389"; // or LDAPS://10.100.10.100:636
            string baseDn = "DC=VFPLC,DC=INT";

            string serviceUser = "svc_adlookup@VFPLC.INT";
            string servicePassword = "YourPassword";

            try
            {
                using (var entry = new System.DirectoryServices.DirectoryEntry(domainPath + "/" + baseDn, serviceUser, servicePassword))
                {
                    using (var searcher = new DirectorySearcher(entry))
                    {
                        searcher.Filter = $"(sAMAccountName={searchUsername})";

                        // Load any attributes you want
                        searcher.PropertiesToLoad.Add("sAMAccountName");
                        searcher.PropertiesToLoad.Add("givenName");
                        searcher.PropertiesToLoad.Add("sn");
                        searcher.PropertiesToLoad.Add("mail");
                        searcher.PropertiesToLoad.Add("displayName");
                        searcher.PropertiesToLoad.Add("department");
                        searcher.PropertiesToLoad.Add("title");
                        searcher.PropertiesToLoad.Add("telephoneNumber");

                        System.DirectoryServices.SearchResult result = searcher.FindOne();
                        if (result == null) return null;

                        return new ADUserModel
                        {
                            Username = GetProp(result, "sAMAccountName"),
                            FirstName = GetProp(result, "givenName"),
                            LastName = GetProp(result, "sn"),
                            Email = GetProp(result, "mail"),
                            DisplayName = GetProp(result, "displayName"),
                            Department = GetProp(result, "department"),
                            Title = GetProp(result, "title"),
                            TelephoneNumber = GetProp(result, "telephoneNumber")
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                return null;
            }
        }


        //public bool Authenticate(string username, string password)
        //{
        //    try
        //    {
        //        using (var cn = new Novell.Directory.Ldap.LdapConnection())
        //        {
        //            cn.Connect(ldapServer, ldapPort);
        //            string userDn = $"uid={username},{baseDn}";
        //            cn.Bind(userDn, password);
        //            return cn.Connected;
        //        }
        //    }
        //    catch
        //    {
        //        return false;
        //    }
        //}


    }
}
