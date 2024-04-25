using System;
using System.ComponentModel;
using System.Net;
using System.Security;
using System.Text.Json;
using System.Windows.Forms;
using CyberArkPASSAPIAuth;

namespace CyberArkPASSAPIUser
{
    public enum MFAMethods
    {
        //This method generates an MFA caching SSH key for you to be used connecting to targets via PSM for SSH.
        [Description("Generate Personal")]
        GeneratePersonal = 0,

        //This method can be triggered by a strong user to generate an MFA caching SSH key for a specific user to be used connecting to targets via PSM for SSH.
        //The user who runs this method requires the following permission in the Vault: Reset Users' Passwords
        [Description("Generate For Someone")]
        GenerateForSomeone = 1,

        //This method deletes your MFA caching SSH key for connecting to targets via PSM for SSH.
        [Description("Delete Personal")]
        DeletePersonal = 2,

        //This method can be triggered by a strong user to delete an MFA caching SSH key for a specific user for connecting to targets via PSM for SSH.
        //The user who runs this method requires the following permission in the Vault: Reset Users' Passwords
        [Description("Delete For Someone")]
        DeleteForSomeone = 3,

        //This method can be triggered by a strong user to delete all MFA caching SSH keys used to connect to targets via PSM for SSH.
        //The user who runs this method requires the following permission in the Vault: Reset Users' Passwords
        [Description("Delete All")]
        DeleteAll = 4
    }
    public static class MFACaching
    {
        public static RequestProperties MFAProperties(MFAMethods Method)
        {
            // Create a return object.
            RequestProperties result = new();

            // Choose the correct URL.
            switch (Method)
            {
                case MFAMethods.GeneratePersonal:
                    result.URL = "/API/Users/Secret/SSHKeys/Cache";
                    result.Method = "POST";
                    result.SuccessCodes.Add(200);
                    result.HasBody = true;
                    result.Body.Add("formats", "Optional");
                    result.Body.Add("keyPassword", "Optional");
                    break;

                case MFAMethods.GenerateForSomeone:
                    result.URL = "/API/Users/{userID}/Secret/SSHKeys/Cache/";
                    result.Method = "POST";
                    result.SuccessCodes.Add(200);
                    result.HasBody = true;
                    result.Body.Add("formats", "Optional");
                    result.Body.Add("keyPassword", "Optional");
                    break;

                case MFAMethods.DeletePersonal:
                    result.URL = "/API/Users/Secret/SSHKeys/Cache/";
                    result.Method = "DELETE";
                    result.SuccessCodes.Add(200);
                    break;

                case MFAMethods.DeleteForSomeone:
                    result.URL = "/API/Users/{userID}/Secret/SSHKeys/Cache/";
                    result.Method = "DELETE";
                    result.SuccessCodes.Add(200);
                    break;

                case MFAMethods.DeleteAll:
                    result.URL = "/API/Users/Secret/SSHKeys/ClearCache/";
                    result.Method = "DELETE";
                    result.SuccessCodes.Add(200);
                    break;
            }

            // Return the object.
            return result;
        }
    }
    
    public class SSHKey
    {
        public string format {  get; set; }
        public string privateKey { get; set; }
        public string keyAlg { get; set; }
        public SSHKey() { }
    }
    public class MFAObject
    {
        public int count { get; set; }
        public int creationTime { get; set; }
        public int expirationTime { get; set; }
        public string publicKey { get; set; }
        public List<SSHKey>? value { get; set; }

        public MFAObject()
        {
            this.count = 0;
            this.creationTime = 0;
            this.expirationTime = 0;
            this.publicKey = "";
        }
        public MFAObject(string WebResult)
        {
            this.count = 0;
            this.creationTime = 0;
            this.expirationTime = 0;
            this.publicKey = "";

            this.ProcessResult(WebResult);
        }
        
        public bool ProcessResult(string WebResult)
        {
            // Create the return object.
            bool processResult = false;

            // Check if the WebResult is null or blank.
            if ((WebResult != null) && (WebResult != ""))
            {
                // Deserialize the string.
                MFAObject data = JsonSerializer.Deserialize<MFAObject>(WebResult);

                // Test the deserialized object.
                if ((data != null))
                {
                    // Test and assign the values.
                    if (data.count != null)
                    {
                        this.count = data.count;
                    }
                    if (data.creationTime != null)
                    {
                        this.creationTime = data.creationTime;
                    }
                    if (data.expirationTime != null)
                    {
                        this.expirationTime = data.expirationTime;
                    }
                    if (data.publicKey != null)
                    {
                        this.publicKey = data.publicKey;
                    }
                    if (data.value != null)
                    {
                        this.value = data.value;
                    }
                }
            }
            
            // Return the object.
            return processResult;
        }
    }
    public static class Users
    {
        public static RequestProperties GetLoggedOnUserDetails()
        {
            // Make return object.
            RequestProperties result = new RequestProperties();

            // Build the request.
            result.URL = "/WebServices/PIMServices.svc/User";
            result.Method = "GET";
            result.SuccessCodes.Add(200);

            // Return result.
            return result;
        }
    }
    public class UserDetails
    {
        public bool AgentUser {  get; set; }
        public bool Disabled { get; set; }
        public bool Suspended { get; set; }
        public bool Expired { get; set; }
        public string Email { get; set; }
        public string ExpiryDate { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Location { get; set; }
        public string Source { get; set; }
        public string UserName { get; set; }
        public string UserTypeName { get; set; }

        public UserDetails()
        {
            // Set default values.
            this.AgentUser = false;
            this.Disabled = false;
            this.Suspended = false;
            this.Expired = false;
            this.Email = string.Empty;
            this.ExpiryDate = string.Empty;
            this.FirstName = string.Empty;
            this.LastName = string.Empty;
            this.Location = string.Empty;
            this.Source = string.Empty;
            this.UserName = string.Empty;
            this.UserTypeName = string.Empty;
        }
        
    }
}