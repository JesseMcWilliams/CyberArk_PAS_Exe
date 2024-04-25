using System.ComponentModel;
using System.Net;
using System.Security;
using System.Text.Json;

namespace CyberArkPASSAPIAuth
{
    public enum AuthMethods
    {
        [Description("CyberArk")]
        CyberArk = 0,

        [Description("LDAP")]
        LDAP = 1,

        [Description("RADIUS")]
        RADIUS = 2,

        [Description("Windows")]
        Windows = 3,

        [Description("PTA")]
        PTA = 4,

        [Description("Shared")]
        Shared = 5,

        [Description("PKI")]
        PKI = 6,

        [Description("PKIPN")]
        PKIPN = 7,

        [Description("SAML")]
        SAML = 8,

        [Description("Logoff")]
        LOGOFF = 9
    }
    
    public static class Authentication
    {
        
        public static RequestProperties AuthProperties(AuthMethods Method)
        {
            // Create a return object.
            RequestProperties result = new();

            // Choose the correct URL.
            switch (Method)
            {
                case AuthMethods.CyberArk:
                    result.URL = "/API/auth/cyberark/logon";
                    result.Method = "POST";
                    result.SuccessCodes.Add(200);
                    result.HasBody = true;
                    result.Body.Add("username", "Mandatory");
                    result.Body.Add("password", "Mandatory");
                    result.Body.Add("newPassword", "Optional");
                    result.Body.Add("concurrentSession", "Optional");
                    break;

                case AuthMethods.LDAP:
                    result.URL = "/API/auth/LDAP/Logon/";
                    result.Method = "POST";
                    result.SuccessCodes.Add(200);
                    result.HasBody = true;
                    result.Body.Add("username", "Mandatory");
                    result.Body.Add("password", "Mandatory");
                    result.Body.Add("newPassword", "Optional");
                    result.Body.Add("concurrentSession", "Optional");
                    break;

                case AuthMethods.RADIUS:
                    result.URL = "/API/auth/RADIUS/Logon/";
                    result.Method = "POST";
                    result.SuccessCodes.Add(200);
                    result.HasBody = true;
                    result.Body.Add("username", "Mandatory");
                    result.Body.Add("password", "Mandatory");
                    result.Body.Add("newPassword", "Optional");
                    result.Body.Add("concurrentSession", "Optional");
                    break;

                case AuthMethods.Windows:
                    result.URL = "/API/auth/Windows/Logon/";
                    result.Method = "POST";
                    result.SuccessCodes.Add(200);
                    result.HasBody = true;
                    result.Body.Add("username", "Mandatory");
                    result.Body.Add("password", "Mandatory");
                    result.Body.Add("newPassword", "Optional");
                    result.Body.Add("concurrentSession", "Optional");
                    break;

                case AuthMethods.PTA:
                    result.URL = "api/getauthtoken/";
                    result.Method = "POST";
                    result.SuccessCodes.Add(200);
                    result.HasBody = true;
                    result.Body.Add("username", "Mandatory");
                    result.Body.Add("password", "Mandatory");
                    break;

                case AuthMethods.Shared:
                    result.URL = "/WebServices/auth/Shared/RestfulAuthenticationService.svc/Logon/";
                    result.Method = "POST";
                    result.SuccessCodes.Add(200);
                    result.HasBody = false;
                    break;

                case AuthMethods.PKI:
                    result.URL = "/API/auth/pki/logon";
                    result.Method = "POST";
                    result.SuccessCodes.Add(200);
                    result.HasBody = true;
                    result.Body.Add("username", "Optional");
                    result.Body.Add("password", "Optional");
                    result.Body.Add("newPassword", "Optional");
                    result.Body.Add("concurrentSession", true);
                    result.Body.Add("secureMode", true);
                    result.Body.Add("apiUse", true);
                    result.Body.Add("type", "pki");
                    result.Body.Add("additionalInfo", "Optional");
                    break;

                case AuthMethods.PKIPN:
                    result.URL = "/API/auth/pkipn/logon";
                    result.Method = "POST";
                    result.SuccessCodes.Add(200);
                    result.HasBody = true;
                    result.Body.Add("username", "Optional");
                    result.Body.Add("password", "Optional");
                    result.Body.Add("newPassword", "Optional");
                    result.Body.Add("concurrentSession", true);
                    result.Body.Add("secureMode", true);
                    result.Body.Add("apiUse", true);
                    result.Body.Add("type", "pkipn");
                    result.Body.Add("additionalInfo", "Optional");
                    break;

                case AuthMethods.SAML:
                    result.URL = "/API/auth/saml/Logon";
                    result.Method = "POST";
                    result.SuccessCodes.Add(200);
                    result.HasBody = true;
                    result.Body.Add("SAMLResponse", "");
                    result.Body.Add("apiUse", true);
                    result.Body.Add("concurrentSession", true);
                    result.ContentType = "application/x-www-form-urlencoded";
                    break;

                case AuthMethods.LOGOFF:
                    result.URL = "/API/Auth/Logoff/";
                    result.Method = "POST";
                    result.SuccessCodes.Add(200);
                    result.HasBody = false;
                    break;

                default:
                    result.URL = "/API/auth/Cyberark/Logon";
                    result.Method = "POST";
                    result.SuccessCodes.Add(200);
                    result.HasBody = true;
                    result.Body.Add("username", "Mandatory");
                    result.Body.Add("password", "Mandatory");
                    result.Body.Add("newPassword", "Optional");
                    result.Body.Add("concurrentSession", "Optional");
                    break;

            }
            // Return the result.
            return result;
        }
        
    }

    public class RequestProperties
    {
        public string URL { get; set; }
        public string Method { get; set; }
        public List<int> SuccessCodes { get; set; }
        public string ContentType { get; set; }
        public bool HasBody { get; set; }
        public Dictionary<string, dynamic> Body { get; set; }
        public bool HasQuery { get; set; }
        public List<string> Query { get; set; }
        public Uri? Uri { get; set; }
        public RequestProperties()
        {
            this.URL = string.Empty;
            this.Method = string.Empty;
            this.SuccessCodes = new List<int>();
            this.ContentType = "application/json";
            this.HasBody = false;
            this.Body = new Dictionary<string, dynamic>();
            this.HasQuery = false;
            this.Query = new List<string>();
            this.Uri = null;
        }
        public string GetBodyParameter(string parameterName)
        {
            // Create return object.
            string result = null;

            // Try to get the result.
            if ((this.Body != null) && (this.Body.ContainsKey(parameterName)))
            {
                // Get the result as a VAR and test it.
                var dynamic = this.Body[parameterName];

                // Test it.
                if (dynamic is string)
                {
                    // It is a string.
                    result = this.Body[parameterName];
                }
                else if (dynamic is string[])
                {
                    // It is a string array.
                    result = string.Join(",", this.Body[parameterName]);
                }
                
            }

            // Return the object.
            return result;
        }
    }
    public class ResultAuthentication
    {
        public SecureString Token { get; set; }
        // This class represents the returned object when authentication occures.
        public ResultAuthentication() { Token = new SecureString(); }
        
        public void TokenFromString(string TokenString)
        {
            // Verify the Token String is not blank.
            if (TokenString != "")
            {
                // Loop over the string and append to the token.
                foreach (char c in TokenString)
                {
                    this.Token.AppendChar(c);
                }
                this.Token.MakeReadOnly();
            }
        }
        public void TokenFromJsonString(string TokenJson)
        {
            // Verify the Token JSON is not blank.
            if (TokenJson != "")
            {
                string jsonString = JsonSerializer.Deserialize<string>(TokenJson);
                this.TokenFromString(jsonString);
            }
            
            
        }
        public string TokenToString()
        {
            return new NetworkCredential(string.Empty, this.Token).Password;
        }
    }
}