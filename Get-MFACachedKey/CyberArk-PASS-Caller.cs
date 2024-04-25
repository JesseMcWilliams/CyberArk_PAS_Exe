using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Net;
using System.Net.Http;
using System.Linq;
using System.ComponentModel;
using Get_MFACachedKey;
using CyberArkPASSAPIAuth;
using CyberArkPASSAPIUser;
using System.Security.Authentication;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Runtime.CompilerServices;
using System.Windows.Forms;
using System;
using getSAMLResponse;


namespace CyberArkPASSCaller
{

    public class CyberArkPASS
    {
        public Uri? BaseURI { get; set; }
        public bool IgnoreSSL { get; set; }
        public int RequestTimeout { get; set; }
        public NetworkCredential UserCredential { get; set; }
        public NetworkCredential newUserCredential { get; set; }
        public X509Certificate2 UserCertificate { get; set; }
        public AuthMethods AuthMethod { get; set; }
        public string? SAMLResponse { get; set; }
        public string UserAgent { get; set; } = "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US)";
        private SecureString? AuthToken { get; set; }
        private HttpClient Client = new();
        private HttpClientHandler Handler = new();
        private Logging Logger = new();
        private Dictionary<int, string> ErrorMessages = new Dictionary<int, string>()
        {
            {10, "Provided credential does not meet the minimum requirements!\r\n\tUsername cannot be blank!\r\n\tPassword must be longer than 4 characters!" },
            {20, "SAML : Failed to get the IDP URL from the web server." }
        };

        public CyberArkPASS(string URL)
        {
            this.BaseURI = new Uri(URL);
            this.AuthToken = null;

            // Call Set Logging
            this.SetLogging("", LogLevel.Verbose);
        }

        public CyberArkPASS(string URL, string LogPath, LogLevel Level)
        {
            this.BaseURI = new Uri(URL);
            this.AuthToken = null;

            // Call Set Logging
            this.SetLogging(LogPath, Level);
        }

        //region Private Methods
        private void SetLogging(string LogPath, LogLevel Level = LogLevel.Error)
        {
            // Check that the provided path is not null or blank.
            if ((LogPath != null) && (LogPath != ""))
            {
                // Provided path is not blank.  Get the fully qualified path.
                string fullPath = System.IO.Path.GetFullPath(LogPath);

                // Get the folder path without the filename.
                string oldFolderPath = Path.GetDirectoryName(fullPath);

                // Get the filename without extension.
                string oldFilename = Path.GetFileNameWithoutExtension(fullPath);

                // Get the extension.
                string oldExtension = Path.GetExtension(fullPath);

                // Create the new file name.
                string newFilename = string.Format("{0}{1}", oldFilename, oldExtension);

                // Create the new fully qualified filename and path.
                if ((oldFolderPath != null) && (oldFolderPath != ""))
                {
                    LogPath = System.IO.Path.Combine(oldFolderPath, newFilename);
                }
                else
                {
                    LogPath = newFilename;
                }
            }
            else
            {
                // Set a default log path.
                string LogName = string.Format("{0}_(HTTP)_Logger{1}", DateTime.Now.ToString("yyyy-MM-dd"), ".log");
                LogPath = System.IO.Path.Combine("Logs", LogName);
            }

            // Build the logger object.
            this.Logger = new(LogPath, Level);
        }
        private bool AuthCyberArk()
        {
            // Create return object.
            bool result = false;

            // Create the token object.
            ResultAuthentication token = new ResultAuthentication();

            // Perform basic validation on the passed in credential.
            if ((this.UserCredential != null) && (this.UserCredential.UserName != "") && (this.UserCredential.Password.Length > 4))
            {
                // The credential is not null, the username is not blank, and the password has more than 4 characters.
                // Create and set the HTTP Client.
                this.Client = this.SetHTTPClient();

                // Get the Authentication Request Properties.
                RequestProperties requestDetails = Authentication.AuthProperties(AuthMethods.CyberArk);

                // Make the call.
                HTTPResult requestResult = ProcessRequest(requestDetails);

                // Check the media type.
                if ((requestResult.Type != null) && (requestResult.Type == "application/json"))
                {
                    // Convert the JSON as generic string.
                    token.TokenFromJsonString(requestResult.Returned);

                    // Save the token to this object.
                    this.AuthToken = token.Token;

                    // Verify Token length before trying to set the Authorization header.
                    if (this.AuthToken.Length >= 200)
                    {
                        // Save the token to the headers.
                        this.Client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(token.TokenToString());

                        // Set the result to true.
                        result = true;
                    }
                    else
                    {
                        this.Logger.WriteError(string.Format("Failed to set the Authorization Token!  \r\n\tToken ({0})", token.TokenToString()));
                    }
                }
            }
            else
            {
                // Write & Throw Error
                int errorCode = 10;
                string errorMessage = string.Format("Code {0} : {1}", errorCode, this.ErrorMessages[errorCode]);
                this.Logger.WriteError(errorMessage);
                throw new InvalidCredentialException(errorMessage);
            }

            return result;
        }
        private bool AuthLdap()
        {
            // Create return object.
            bool result = false;

            // Create the token object.
            ResultAuthentication token = new ResultAuthentication();

            // Perform basic validation on the passed in credential.
            if ((this.UserCredential != null) && (this.UserCredential.UserName != "") && (this.UserCredential.Password.Length > 4))
            {
                // The credential is not null, the username is not blank, and the password has more than 4 characters.
                // Create and set the HTTP Client.
                this.Client = this.SetHTTPClient();

                // Get the Authentication Request Properties.
                RequestProperties requestDetails = Authentication.AuthProperties(AuthMethods.LDAP);

                // Make the call.
                HTTPResult requestResult = ProcessRequest(requestDetails);

                // Check the media type.
                if ((requestResult.Type != null) && (requestResult.Type == "application/json"))
                {
                    // Convert the JSON as generic string.
                    token.TokenFromJsonString(requestResult.Returned);

                    // Save the token to this object.
                    this.AuthToken = token.Token;

                    // Verify Token length before trying to set the Authorization header.
                    if (this.AuthToken.Length >= 200)
                    {
                        // Save the token to the headers.
                        this.Client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(token.TokenToString());

                        // Set the result to true.
                        result = true;
                    }
                    else
                    {
                        this.Logger.WriteError(string.Format("Failed to set the Authorization Token!  \r\n\tToken ({0})", token.TokenToString()));
                    }
                }
            }
            else
            {
                // Write & Throw Error
                int errorCode = 10;
                string errorMessage = string.Format("Code {0} : {1}", errorCode, this.ErrorMessages[errorCode]);
                this.Logger.WriteError(errorMessage);
                throw new InvalidCredentialException(errorMessage);
            }

            return result;
        }
        private bool AuthRadius()
        {
            // Create return object.
            bool result = false;

            // Create the token object.
            ResultAuthentication token = new ResultAuthentication();

            // Perform basic validation on the passed in credential.
            if ((this.UserCredential != null) && (this.UserCredential.UserName != "") && (this.UserCredential.Password.Length > 4))
            {
                // The credential is not null, the username is not blank, and the password has more than 4 characters.
                // Create and set the HTTP Client.
                this.Client = this.SetHTTPClient();

                // Get the Authentication Request Properties.
                RequestProperties requestDetails = Authentication.AuthProperties(AuthMethods.RADIUS);

                // Make the call.
                HTTPResult requestResult = ProcessRequest(requestDetails);

                // Check the media type.
                if ((requestResult.Type != null) && (requestResult.Type == "application/json"))
                {
                    // Convert the JSON as generic string.
                    token.TokenFromJsonString(requestResult.Returned);

                    // Save the token to this object.
                    this.AuthToken = token.Token;

                    // Verify Token length before trying to set the Authorization header.
                    if (this.AuthToken.Length >= 200)
                    {
                        // Save the token to the headers.
                        this.Client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(token.TokenToString());

                        // Set the result to true.
                        result = true;
                    }
                    else
                    {
                        this.Logger.WriteError(string.Format("Failed to set the Authorization Token!  \r\n\tToken ({0})", token.TokenToString()));
                    }
                }
            }
            else
            {
                // Write & Throw Error
                int errorCode = 10;
                string errorMessage = string.Format("Code {0} : {1}", errorCode, this.ErrorMessages[errorCode]);
                this.Logger.WriteError(errorMessage);
                throw new InvalidCredentialException(errorMessage);
            }

            return result;
        }
        private bool AuthWindows()
        {
            // Create return object.
            bool result = false;

            // Create the token object.
            ResultAuthentication token = new ResultAuthentication();

            // Perform basic validation on the passed in credential.
            if ((this.UserCredential != null) && (this.UserCredential.UserName != "") && (this.UserCredential.Password.Length > 4))
            {
                // The credential is not null, the username is not blank, and the password has more than 4 characters.
                // Create and set the HTTP Client.
                this.Client = this.SetHTTPClient();

                // Get the Authentication Request Properties.
                RequestProperties requestDetails = Authentication.AuthProperties(AuthMethods.Windows);

                // Make the call.
                HTTPResult requestResult = ProcessRequest(requestDetails);

                // Check the media type.
                if ((requestResult.Type != null) && (requestResult.Type == "application/json"))
                {
                    // Convert the JSON as generic string.
                    token.TokenFromJsonString(requestResult.Returned);

                    // Save the token to this object.
                    this.AuthToken = token.Token;

                    // Verify Token length before trying to set the Authorization header.
                    if (this.AuthToken.Length >= 200)
                    {
                        // Save the token to the headers.
                        this.Client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(token.TokenToString());

                        // Set the result to true.
                        result = true;
                    }
                    else
                    {
                        this.Logger.WriteError(string.Format("Failed to set the Authorization Token!  \r\n\tToken ({0})", token.TokenToString()));
                    }
                }
            }
            else
            {
                // Write & Throw Error
                int errorCode = 10;
                string errorMessage = string.Format("Code {0} : {1}", errorCode, this.ErrorMessages[errorCode]);
                this.Logger.WriteError(errorMessage);
                throw new InvalidCredentialException(errorMessage);
            }

            return result;
        }
        private bool AuthPta()
        {
            // Create return object.
            bool result = false;

            // Create the token object.
            ResultAuthentication token = new ResultAuthentication();

            // Perform basic validation on the passed in credential.
            if ((this.UserCredential != null) && (this.UserCredential.UserName != "") && (this.UserCredential.Password.Length > 4))
            {
                // The credential is not null, the username is not blank, and the password has more than 4 characters.
                // Create and set the HTTP Client.
                this.Client = this.SetHTTPClient();

                // Get the Authentication Request Properties.
                RequestProperties requestDetails = Authentication.AuthProperties(AuthMethods.PTA);

                // Make the call.
                HTTPResult requestResult = ProcessRequest(requestDetails);

                // Check the media type.
                if ((requestResult.Type != null) && (requestResult.Type == "application/json"))
                {
                    // Convert the JSON as generic string.
                    token.TokenFromJsonString(requestResult.Returned);

                    // Save the token to this object.
                    this.AuthToken = token.Token;

                    // Verify Token length before trying to set the Authorization header.
                    if (this.AuthToken.Length >= 200)
                    {
                        // Save the token to the headers.
                        this.Client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(token.TokenToString());

                        // Set the result to true.
                        result = true;
                    }
                    else
                    {
                        this.Logger.WriteError(string.Format("Failed to set the Authorization Token!  \r\n\tToken ({0})", token.TokenToString()));
                    }
                }
            }
            else
            {
                // Write & Throw Error
                int errorCode = 10;
                string errorMessage = string.Format("Code {0} : {1}", errorCode, this.ErrorMessages[errorCode]);
                this.Logger.WriteError(errorMessage);
                throw new InvalidCredentialException(errorMessage);
            }

            return result;
        }
        private bool AuthShared()
        {
            return true;
        }
        private bool AuthPki()
        {
            // Create return object.
            bool result = false;

            // Create the token object.
            ResultAuthentication token = new ResultAuthentication();

            // Perform basic validation on the passed in credential.
            if ((this.UserCertificate != null) && (this.UserCertificate.Subject != "") && (this.UserCertificate.HasPrivateKey))
            {
                // The certificate is not null, the subject is not blank, and it has the private key.
                // Create and set the HTTP Client.
                this.Client = this.SetHTTPClient(this.UserCertificate);

                // Get the Authentication Request Properties.
                RequestProperties requestDetails = Authentication.AuthProperties(AuthMethods.PKI);

                // Make the call.
                HTTPResult requestResult = ProcessRequest(requestDetails);

                // Check the media type.
                if ((requestResult.Type != null) && (requestResult.Type == "application/json"))
                {
                    // Convert the JSON as generic string.
                    token.TokenFromJsonString(requestResult.Returned);

                    // Save the token to this object.
                    this.AuthToken = token.Token;

                    // Verify Token length before trying to set the Authorization header.
                    if (this.AuthToken.Length >= 200)
                    {
                        // Save the token to the headers.
                        this.Client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(token.TokenToString());

                        // Set the result to true.
                        result = true;
                    }
                    else
                    {
                        this.Logger.WriteError(string.Format("Failed to set the Authorization Token!  \r\n\tToken ({0})", token.TokenToString()));
                    }
                }
            }
            else
            {
                // Write & Throw Error
                int errorCode = 10;
                string errorMessage = string.Format("Code {0} : {1}", errorCode, this.ErrorMessages[errorCode]);
                this.Logger.WriteError(errorMessage);
                throw new InvalidCredentialException(errorMessage);
            }

            return result;
        }
        private bool AuthPkiPn()
        {
            // Create return object.
            bool result = false;

            // Create the token object.
            ResultAuthentication token = new ResultAuthentication();

            // Perform basic validation on the passed in credential.
            if ((this.UserCertificate != null) && (this.UserCertificate.Subject != "") && (this.UserCertificate.HasPrivateKey))
            {
                // The certificate is not null, the subject is not blank, and it has the private key.
                // Create and set the HTTP Client.
                this.Client = this.SetHTTPClient(this.UserCertificate);

                // Get the Authentication Request Properties.
                RequestProperties requestDetails = Authentication.AuthProperties(AuthMethods.PKIPN);

                // Make the call.
                HTTPResult requestResult = ProcessRequest(requestDetails);

                // Check the media type.
                if ((requestResult.Type != null) && (requestResult.IsSuccess) && (requestResult.Type == "application/json"))
                {
                    // Convert the JSON as generic string.
                    token.TokenFromJsonString(requestResult.Returned);

                    // Save the token to this object.
                    this.AuthToken = token.Token;

                    // Verify Token length before trying to set the Authorization header.
                    if (this.AuthToken.Length >= 200)
                    {
                        // Save the token to the headers.
                        this.Client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(token.TokenToString());

                        // Set the result to true.
                        result = true;
                    }
                    else
                    {
                        this.Logger.WriteError(string.Format("Failed to set the Authorization Token!  \r\n\tToken ({0})", token.TokenToString()));
                    }
                }
                else
                {
                    this.Logger.WriteError(string.Format("Authentication Failed!\r\n\tResult:  {0}", requestResult.Returned));
                }
            }
            else
            {
                // Write & Throw Error
                int errorCode = 10;
                string errorMessage = string.Format("Code {0} : {1}", errorCode, this.ErrorMessages[errorCode]);
                this.Logger.WriteError(errorMessage);
                throw new InvalidCredentialException(errorMessage);
            }

            return result;
        }
        private bool AuthSaml()
        {
            // Create return object.
            bool result = false;

            // Create the SAML object.
            string SAML = string.Empty;

            // Create the token object.
            ResultAuthentication token = new ResultAuthentication();

            // Create and set the HTTP Client.
            this.Client = this.SetHTTPClient();

            // Get the Authentication Request Properties.
            RequestProperties requestDetails = Authentication.AuthProperties(AuthMethods.SAML);

            // Make the call.
            HTTPResult requestResult = ProcessRequest(requestDetails);

            // Check the media type.
            if ((requestResult != null) && (requestResult.IsSuccess) && (requestResult.Type != null) && (requestResult.Type == "application/json"))
            {
                // We should get a redirect URL from the request result.

                // Test the result.
                if ((requestResult.Returned != null) && (requestResult.Returned != ""))
                {
                    // Convert returned from json.
                    string fullURL = JsonSerializer.Deserialize<string>(requestResult.Returned);

                    // Create form object
                    Form1 mySSO = new Form1(fullURL);

                    // Create and Call WebView2 by allynl93 (https://github.com/allynl93/getSAMLResponse-Interactive/tree/main)
                    Application.EnableVisualStyles();

                    // Launch the form to get the user input.
                    Application.Run(mySSO);

                    // Check if the data is available.
                    if ((mySSO.samlResponse != null) && (mySSO.samlResponse != string.Empty))
                    {
                        // Get the SAML Response from the web call.
                        SAML = mySSO.samlResponse;

                        // Set the SAML Response in the request body.
                        requestDetails.Body["SAMLResponse"] = SAML;
                        

                        // Set the request content type.
                        requestDetails.ContentType = "application/x-www-form-urlencoded";

                        // Submit the request for the Authentication Token.
                        HTTPResult authRequestResult = ProcessRequest(requestDetails);

                        // Test the Auth Request Result.
                        if ((authRequestResult != null) && (authRequestResult.IsSuccess))
                        {
                            // Check the media type.
                            if ((authRequestResult.Type != null) && (authRequestResult.Type == "application/json"))
                            {
                                // Convert the JSON as generic string.
                                token.TokenFromJsonString(authRequestResult.Returned);

                                // Save the token to this object.
                                this.AuthToken = token.Token;

                                // Verify Token length before trying to set the Authorization header.
                                if ((this.AuthToken.Length >= 200) && (this.AuthToken.Length <= 300))
                                {
                                    // Save the token to the headers.
                                    this.Client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(token.TokenToString());

                                    // Set the result to true.
                                    result = true;
                                }
                                else
                                {
                                    this.Logger.WriteError(string.Format("Failed to set the Authorization Token!  \r\n\tToken ({0})", token.TokenToString()));
                                }
                            }
                        }
                                
                        else
                        {
                            this.Logger.WriteError("Failed to get the authentication token!");

                            if (authRequestResult != null)
                            {
                                this.Logger.WriteError(string.Format("Returned!\r\n\t{0}", authRequestResult.Returned));
                                this.Logger.WriteError(string.Format("Error Details!\r\n\t{0}", authRequestResult.ErrorDetails));
                            }
                                    
                        }

                    }
                }
            }
                
            else
            {
                // Write & Throw Error
                int errorCode = 20;
                string errorMessage = string.Format("Code {0} : {1}", errorCode, this.ErrorMessages[errorCode]);
                this.Logger.WriteError(errorMessage);
                throw new InvalidCredentialException(errorMessage);
            }

            return result;
        }
        private HttpClientHandler GetHttpClientHandler()
        {
            // Is IgnoreSSL true?
            if (this.IgnoreSSL)
            {
                // Create a custom handler to ignore the SSL errors.
                var handler = new HttpClientHandler();
                handler.ClientCertificateOptions = ClientCertificateOption.Manual;
                handler.ServerCertificateCustomValidationCallback =
                    (httpRequestMessage, cert, cetChain, policyErrors) =>
                    {
                        return true;
                    };

                return handler;
            }
            else
            {
                return new HttpClientHandler();
            }
        }
        private HttpClient SetHTTPClient()
        {
            // Create the new HTTP Client Handler.
            this.Handler = GetHttpClientHandler();

            // Set the timeout period on the handler.
            HttpClient myClient = new HttpClient(this.Handler)
            {
                Timeout = new TimeSpan(0, 0, this.RequestTimeout),
                BaseAddress = this.BaseURI
            };

            // Set the user agent.
            myClient.DefaultRequestHeaders.Add("User-Agent", this.UserAgent);

            return myClient;
        }
        private HttpClient SetHTTPClient(NetworkCredential UserCredential, string HTTPAuthType)
        {
            // Create a new credential cache.
            CredentialCache credentialsCache = new CredentialCache();

            // Add the provided credential to the credential cache.
            credentialsCache.Add(this.BaseURI, HTTPAuthType, UserCredential);

            // Create the new HTTP Client Handler and set Pre Authenticate to true.
            this.Handler = GetHttpClientHandler();
            this.Handler.Credentials = credentialsCache;
            this.Handler.PreAuthenticate = true;

            // Set the timeout period on the handler.
            HttpClient myClient = new HttpClient(this.Handler)
            {
                Timeout = new TimeSpan(0, 0, this.RequestTimeout),
                BaseAddress = this.BaseURI
            };

            // Set the user agent.
            myClient.DefaultRequestHeaders.Add("User-Agent", this.UserAgent);

            return myClient;
        }
        private HttpClient SetHTTPClient(X509Certificate2 UserCertificate)
        {
            
            // Create the new HTTP Client Handler.
            this.Handler = GetHttpClientHandler();

            // Add the client certificate.
            this.Handler.ClientCertificates.Add(UserCertificate);

            // Set the client certificate options.
            this.Handler.ClientCertificateOptions = ClientCertificateOption.Manual;

            // Set the protocols for the certificate.
            this.Handler.SslProtocols = SslProtocols.Tls12;

            // Set the timeout period on the handler.
            HttpClient myClient = new HttpClient(this.Handler)
            {
                Timeout = new TimeSpan(0, 0, this.RequestTimeout),
                BaseAddress = this.BaseURI
            };

            // Set the user agent.
            myClient.DefaultRequestHeaders.Add("User-Agent", this.UserAgent);

            return myClient;
        }

        private HTTPResult SendRequest(HttpClient httpClient, Uri pathURI, string Method, Dictionary<string, dynamic>? Body = null, string ContentType = "application/json")
        {
            // Build the return object.
            HTTPResult result = new HTTPResult();

            // Create the Cancellation Token Source.
            CancellationTokenSource cts = new CancellationTokenSource();
            CancellationToken token = cts.Token;

            // Create request content.
            HttpContent requestContent = new StringContent("");

            // Create variable to hold the request.
            Task<HttpResponseMessage>? requestTask = null;

            // Create variable to hold the Body as HTTP Conent.
            HttpContent? submitContent = null;

            // Create variable to hold the Body as a serialized JSON string.
            string rawJson = "";

            // Create the JSON options.
            var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
            jsonOptions.Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping;

            // If the body is not null add it to submitContnet.
            if (Body != null)
            {
                // Replace the Password in the JSON string if it is not null.
                if ((this.UserCredential != null) && (Body != null) && (Body.ContainsKey("password")))
                {
                    Body["password"] = this.UserCredential.Password;
                }

                // Replace the Password in the JSON string if it is not null.
                if ((this.UserCredential != null) && (Body != null) && (Body.ContainsKey("newPassword")))
                {
                    Body["newPassword"] = this.newUserCredential.Password;
                }

                // Convert the Dictionary to a JSON object.
                rawJson = JsonSerializer.Serialize(Body, jsonOptions);

                // Create the content and set the content type.
                submitContent = new StringContent($"{rawJson}", Encoding.UTF8, ContentType);
            }

            // Create variable to hold the HTTP Response Message.
            HttpResponseMessage? httpResponseMessage = null;

            // Create a try catch.
            try
            {
                // Send the Request.
                switch (Method.ToUpper())
                {
                    case "POST":
                        requestTask = httpClient.PostAsync(pathURI, submitContent, cts.Token);
                        break;

                    case "PUT":
                        requestTask = httpClient.PutAsync(pathURI, submitContent, cts.Token);
                        break;

                    case "PATCH":
                        requestTask = httpClient.PatchAsync(pathURI, submitContent, cts.Token);
                        break;

                    case "DELETE":
                        requestTask = httpClient.DeleteAsync(pathURI, cts.Token);
                        break;

                    case "GET":
                        requestTask = httpClient.GetAsync(pathURI, cts.Token);
                        break;
                }

                // Get the result if the task is not null.
                if (requestTask != null)
                {
                    httpResponseMessage = requestTask.Result;
                }
            }
            catch (System.AggregateException ae)
            {
                this.Logger.WriteError(string.Format("Incorrect PIN or no PIN provided when prompted!"));
                this.Logger.WriteError(string.Format("{0}", ae.Message));

                Exception? innerE = ae.InnerException;
                do
                {
                    // Test if the current inner exception is null.
                    if (innerE != null)
                    {
                        // Test if the current inner exception message is null or blank.
                        if ((innerE.Message != null) && (innerE.Message != ""))
                        {
                            this.Logger.WriteError(string.Format("{0}", innerE.Message));
                        }
                        
                        // Get the nested inner exception.  Even if null.
                        innerE = innerE.InnerException;
                    }
                    
                }
                while (innerE != null);

                throw new ArgumentException("Failed to access the Private Key!");
            }
            

            // Check if the httpResponseMessage is null.
            if (httpResponseMessage != null)
            {
                // Check if the request is successful.
                if (httpResponseMessage.IsSuccessStatusCode)
                {
                    // Set the value in the response.
                    result.IsSuccess = httpResponseMessage.IsSuccessStatusCode;
                }

                // Assign the Status Code and the Status Message.
                result.StatusCode = ((int)httpResponseMessage.StatusCode);
                result.StatusMessage = httpResponseMessage.ReasonPhrase;

                // Assign the Response Content if it isn't null.
                if (httpResponseMessage.Content != null)
                {
                    // Read the content.
                    var responseContent = httpResponseMessage.Content.ReadAsStringAsync();

                    // Wait for the Response Content to be read.
                    DateTime waitStart = DateTime.Now;
                    //(waitStart < (waitStart.AddSeconds(this.RequestTimeout))) | 
                    while ((responseContent.Status != TaskStatus.RanToCompletion))
                    {
                        // Pause.
                        System.Threading.Thread.Sleep(500);

                        // Check if maximum wait time has been exceeded.
                        if (waitStart < (waitStart.AddSeconds(this.RequestTimeout)))
                        {
                            break;
                        }
                    }

                    // Check if the response was fully read.
                    if ((responseContent != null) && (responseContent.Status == TaskStatus.RanToCompletion))
                    {
                        // Check if Result is null.
                        if (responseContent.Result != null)
                        {
                            // Write the raw data to Returned.
                            result.Returned = responseContent.Result;
                        }
                        // Check if Headers is null.
                        if (httpResponseMessage.Content.Headers != null)
                        {
                            if (httpResponseMessage.Content.Headers.ContentType != null)
                            {
                                // Check the media type.
                                if ((httpResponseMessage.Content.Headers.ContentType.MediaType != null))
                                {
                                    // Set the media type on the HTTP Result.
                                    result.Type = httpResponseMessage.Content.Headers.ContentType.MediaType.ToLower();
                                }
                                else
                                {
                                    // Warning Occured.
                                    this.Logger.WriteWarning(string.Format("Warning Occurred in web request!  {0}\r\n\tThis may be normal.", "Media Type is NULL!"));
                                }
                            }
                            else
                            {
                                // Error Occured.
                                this.Logger.WriteError(string.Format("Error Occurred in web request!  {0}", "Content Type is NULL!"));
                            }
                        }
                        else
                        {
                            // Error Occured.
                            this.Logger.WriteError(string.Format("Error Occurred in web request!  {0}", "Headers is NULL!"));
                        }
                    }
                    else
                    {
                        // Error Occured.
                        this.Logger.WriteError(string.Format("Error Occurred in web request!  {0}", "Response Content is NULL!"));
                    }
                }
                else
                {
                    // Error Occured.
                    this.Logger.WriteError(string.Format("Error Occurred in web request!  {0}", "HTTP Response Content is NULL!"));
                }

                // If Debug or higher is enabled write output.
                if (this.Logger.Level >= LogLevel.Debug)
                {
                    // If Auth Method is PKI or PKIPN get the client certificate used from the HTTP Client Handler.
                    if (((this.AuthMethod == AuthMethods.PKI) | (this.AuthMethod == AuthMethods.PKIPN)) && (this.Handler != null) && (this.AuthToken == null))
                    {
                        // Get the client certificate.
                        X509CertificateCollection clientCerts = this.Handler.ClientCertificates;

                        // Test the certificate collection.
                        if ((clientCerts != null) && (clientCerts.Count > 0))
                        {
                            // Get the first certificate.
                            X509Certificate2 clientCert = clientCerts[0] as X509Certificate2;

                            // Test if the certificate is null or blank.
                            if ((clientCert != null) && (clientCert.Subject != null))
                            {
                                // Output the Client Authentication Certificate information.
                                this.Logger.WriteDebug(string.Format(" Client Cert Subject  :  {0}", clientCert.Subject));
                                this.Logger.WriteDebug(string.Format("  Client Cert Issuer  :  {0}", clientCert.Issuer));
                                this.Logger.WriteDebug(string.Format("Client Cert Not Before:  {0}", clientCert.NotBefore));
                                this.Logger.WriteDebug(string.Format("Client Cert Not After :  {0}", clientCert.NotAfter));
                                this.Logger.WriteDebug(string.Format("  Client Private Key  :  {0}", clientCert.HasPrivateKey));
                                this.Logger.WriteDebug(string.Format("   Client Thumbprint  :  {0}", clientCert.Thumbprint));
                            }
                        }
                    }
                    // Get the client handler to 
                    this.Logger.WriteDebug(string.Format("    HTTP Status Code :  {0}", result.StatusCode));
                    this.Logger.WriteDebug(string.Format(" HTTP Status Message :  {0}", result.StatusMessage));
                    
                    this.Logger.WriteDebug(string.Format("HTTP Request Message :\r\n\t-->  {0}", httpResponseMessage.RequestMessage.ToString().Replace(",", "\r\n\t    ")));
                    this.Logger.WriteDebug(string.Format("     Response Length :  {0}", httpResponseMessage.Content.Headers.ContentLength));

                    // Get the current cookies.
                    if ((this.Handler != null) && (this.Handler.CookieContainer != null) && (this.Handler.CookieContainer.Count > 0))
                    {
                        // The Cookie Container is not null and has at least 1 cookie.  Get all cookies.
                        CookieCollection cookieCollection = this.Handler.CookieContainer.GetAllCookies();

                        // Count Cookies.
                        int clCount = 0;

                        this.Logger.WriteDebug(string.Format(" ********** Cookies Start **********", clCount));

                        // Loop over the cookies.
                        foreach (Cookie cookie in cookieCollection)
                        {
                            // Increment cookie count.
                            clCount++;

                            // Output Cookie information.
                            this.Logger.WriteDebug(string.Format(" ********** {0} **********", clCount));
                            this.Logger.WriteDebug(string.Format("    Name  :  {0}", cookie.Name));
                            this.Logger.WriteDebug(string.Format("   Value  :  {0}", cookie.Value));
                            this.Logger.WriteDebug(string.Format(" Comment  :  {0}", cookie.Comment));
                            this.Logger.WriteDebug(string.Format(" Version  :  {0}", cookie.Version));
                        }
                        this.Logger.WriteDebug(string.Format(" ********** Cookies Finish **********", clCount));
                    }

                    // Get the body that was sent.
                    if ((rawJson != null) && (rawJson != ""))
                    {
                        // Clean the Body of secret data.
                        if (Body != null)
                        {
                            // Password
                            if (Body.ContainsKey("password"))
                            {
                                Body["password"] = "************";
                            }
                            // newPassword
                            if (Body.ContainsKey("newPassword"))
                            {
                                Body["newPassword"] = "************";
                            }
                            // keyPassword
                            if (Body.ContainsKey("keyPassword"))
                            {
                                Body["keyPassword"] = "************";
                            }
                            // Convert the Body to a JSON string with indents.
                            string cleanJson = JsonSerializer.Serialize(Body, jsonOptions);

                            // Replace the Password in the JSON string.
                            this.Logger.WriteVerbose(string.Format("Request Body (Start) : ***********************\r\n{0}", cleanJson));
                            this.Logger.WriteVerbose(string.Format("Request Body (End)   : ***********************"));
                        }
                    }

                    // Get the response body that was received.
                    if ((result.Returned != null))
                    {
                        // Output the response.
                        this.Logger.WriteVerbose(string.Format("Response Body (Start) : ***********************\r\n{0}", result.Returned));
                        this.Logger.WriteVerbose(string.Format("Response Body (End)   : ***********************"));
                    }
                }
            }

            // Return the results.
            return result;
        }

        //endRegion Private Methods

        //region Public Methods
        public void FlushCookies()
        {
            // Get the current base url without path.
            UriBuilder baseURL = new UriBuilder(this.BaseURI.Scheme, this.BaseURI.Host);

            // Get the cookie container from the handler.
            CookieContainer cc = this.Handler.CookieContainer;

            // Get all cookies.
            CookieCollection allCookies = cc.GetAllCookies();


            // Flush the current cookies.  Create an empty container and set it on the handler.
            // Get the current cookies.
            if ((this.Handler != null) && (this.Handler.CookieContainer != null) && (this.Handler.CookieContainer.Count > 0))
            {
                // The Cookie Container is not null and has at least 1 cookie.  Get all cookies.
                CookieCollection cookieCollection = this.Handler.CookieContainer.GetAllCookies();

                // Loop over the cookies.
                foreach (Cookie cookie in cookieCollection)
                {
                    // Expire the cookie.
                    cookie.Expired = true;
                }
            }

            this.Logger.WriteInfo("Cookies Cleared!");
        }
        public bool Authenticate(AuthMethods Method, NetworkCredential? UserCredential = null, X509Certificate2? ClientCertificate = null)
        {
            this.Logger.WriteDebug(string.Format("Authenticating to \r\n\t CyberArk PVWA Address: {0} \r\n\t Authentication Method: {1}", this.BaseURI, Method));

            // Create return object.
            bool result = false;

            // Choose the correct method for the requested authentication method.
            switch (Method)
            {
                case AuthMethods.CyberArk:
                    result = this.AuthCyberArk();
                    break;

                case AuthMethods.LDAP:
                    result = this.AuthLdap();
                    break;

                case AuthMethods.Windows:
                    result = this.AuthWindows();
                    break;

                case AuthMethods.RADIUS:
                    result = this.AuthRadius();
                    break;

                case AuthMethods.PTA:
                    result = this.AuthPta();
                    break;

                case AuthMethods.Shared:
                    result = this.AuthShared();
                    break;

                case AuthMethods.PKI:
                    result = this.AuthPki();
                    break;

                case AuthMethods.PKIPN:
                    result = this.AuthPkiPn();
                    break;

                case AuthMethods.SAML:
                    result = this.AuthSaml();
                    break;

            }
            if (result)
            {
                // Success
                this.Logger.WriteInfo("CyberArk Authentication Token Retrieved.");
            }
            else
            {
                // Failed
                this.Logger.WriteError("Failed to Retrieve the CyberArk Authentication Token!");
            }

            return result;
        }
        public void Logoff()
        {
            // Check for an existing authentication token.
            if ((this.AuthToken != null) && (this.AuthToken.Length > 0))
            {
                // Call the Logoff API.
                // Get the Authentication Request Properties.
                RequestProperties requestDetails = Authentication.AuthProperties(AuthMethods.LOGOFF);

                // Make the call.
                HTTPResult requestResult = ProcessRequest(requestDetails);

                // Check the result.
                if ((requestResult != null) && (requestResult.IsSuccess))
                {
                    if ((requestResult.Type != null) && (requestResult.Type == "application/json"))
                    {
                        // Convert the JSON as a dictionary.
                        Dictionary<string, string> result = JsonSerializer.Deserialize<Dictionary<string, string>>(requestResult.Returned);

                        // Check for a logoff URL.
                        string logoffURL = "";
                        if ((result != null) && (result.ContainsKey("LogoffUrl")))
                        {
                            logoffURL = result["LogoffUrl"];
                        }

                        // Write status.
                        this.Logger.WriteInfo(string.Format("Logged off.  \r\n\t{0}", logoffURL));
                    }
                }
                else
                {
                    this.Logger.WriteError("Failed to Logoff!");
                }


                // Clear the AuthToken.
                this.AuthToken.Dispose();

                // Clear the Default request Headers.
                this.Client.DefaultRequestHeaders.Clear();

                // Dispose of HTTP Client.
                this.Client.Dispose();
            }
        }
        public HTTPResult ProcessRequest(RequestProperties RequestDetails)
        {
            // Build the return object.
            HTTPResult result = new HTTPResult();

            // Create a list of Methods that require a body.
            string[] bodyRequired = { "POST", "PUT", "PATCH" };

            // Check if a body is required.
            if ((RequestDetails != null) && (RequestDetails.Method != null) && (RequestDetails.Method != ""))
            {
                // Build the new URI for the request.
                string basePath = this.Client.BaseAddress.AbsolutePath;
                basePath = Utilities.JoinURL(basePath, RequestDetails.URL);

                // Check if there is query information.
                if (RequestDetails.HasQuery)
                {
                    // Build the query.
                    string requestQuery = "?";

                    // Loop over the query properties.
                    foreach (string query in RequestDetails.Query)
                    {
                        //  Append to the string.
                        requestQuery += string.Format("{0}&", query);

                    }

                    // Strip the trailing ampersand '&'
                    requestQuery = requestQuery.TrimEnd('&');

                    // Set the Query on the URI.
                    basePath += requestQuery;

                    // Build a new URI and add to Request Details with Query information.
                    RequestDetails.Uri = new Uri(this.Client.BaseAddress, basePath);
                }
                else
                {
                    // Build a new URI and add to Request Details without Query information.
                    RequestDetails.Uri = new Uri(this.Client.BaseAddress, basePath);
                }

                // Write Verbose output.
                this.Logger.WriteInfo(string.Format("Processing Request:  " +
                    "\r\n\t  Scheme: {0} " +
                    "\r\n\t  Host  : {1} " +
                    "\r\n\t  Path  : {2} " +
                    "\r\n\t Query  : {3} " +
                    "\r\n\tMethod  : {4} " +
                    "\r\n\tFull URL: {5}", RequestDetails.Uri.Scheme, RequestDetails.Uri.Host, RequestDetails.Uri.AbsolutePath, RequestDetails.Uri.Query, RequestDetails.Method, RequestDetails.Uri.AbsoluteUri));

                if (bodyRequired.Contains(RequestDetails.Method))
                {
                    // Check if a body is present.
                    if ((RequestDetails != null) && (RequestDetails.HasBody))
                    {
                        // Test the body properties.
                        if ((RequestDetails.Body != null) && (RequestDetails.Body.Count > 0))
                        {
                            // Body is not null and has at least 1 value.
                            // Check for username.
                            if ((RequestDetails.Body.ContainsKey("username")) && (this.UserCredential != null))
                            {
                                RequestDetails.Body["username"] = this.UserCredential.UserName;
                            }
                            else
                            {
                                // Remove the username and password.
                                RequestDetails.Body.Remove("username");
                                RequestDetails.Body.Remove("password");
                            }

                            // Check for password.
                            if (RequestDetails.Body.ContainsKey("password"))
                            {
                                RequestDetails.Body["password"] = "";
                            }

                            // Check for a new Password.
                            if ((RequestDetails.Body.ContainsKey("newPassword")) && (this.newUserCredential != null))
                            {
                                RequestDetails.Body["newPassword"] = this.newUserCredential.Password;
                            }

                            // Check for additional parameters that are optional and not set.
                            string[] bodyKeys = RequestDetails.Body.Keys.ToArray();
                            foreach (string key in bodyKeys)
                            {
                                // Get the object value.
                                var keyValue = RequestDetails.Body[key];

                                // Check the Value is not null.
                                if (keyValue != null)
                                {
                                    // Check the value type.
                                    if (keyValue.GetType() == typeof(string))
                                    {
                                        // Value is string.
                                        if (RequestDetails.Body[key].ToUpper() == "OPTIONAL")
                                        {
                                            // Remove the key.
                                            RequestDetails.Body.Remove(key);
                                        }
                                    }
                                    else if (keyValue.GetType() == typeof(string[]))
                                    {
                                        // Value is string[]
                                        if (keyValue.Length == 0)
                                        {
                                            // Remove the key.
                                            RequestDetails.Body.Remove(key);
                                        }
                                    }
                                }


                            }
                        }
                    }
                }

                // Make the web request using the HTTP Client after choosing the method.
                result = SendRequest(this.Client, RequestDetails.Uri, RequestDetails.Method, RequestDetails.Body, RequestDetails.ContentType);

            }

            // Return the results.
            return result;
        }
        public MFAObject GetMFASSHKey(string KeyFormat = "PEM", bool KeyPassphraseRequired = false, string VaultUser = "")
        {
            // Create the return object.
            MFAObject mFAObject = null;

            // Create the request details.
            RequestProperties requestProperties = new();

            // Choose the person.  Current User or someone else.
            if (VaultUser == "")
            {
                // Create the SSH key(s) for the current user.
                requestProperties = MFACaching.MFAProperties(MFAMethods.GeneratePersonal);
            }
            else
            {
                // Create the SSH key(s) for the specified user.
                requestProperties = MFACaching.MFAProperties(MFAMethods.GenerateForSomeone);

                // Replace the target user.
                requestProperties.URL = requestProperties.URL.Replace("{userID}", VaultUser);
            }

            // Create JSON Serializer Options
            JsonSerializerOptions jsonSerializerOptions = new JsonSerializerOptions();
            jsonSerializerOptions.Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping;

            // Check if the Key Format was specified.
            if ((KeyFormat != null) && (KeyFormat != "") && (requestProperties != null) && (requestProperties.Body != null) && (requestProperties.Body.ContainsKey("formats")))
            {
                // Split the key format into a string array.
                string[] rawFormats = KeyFormat.Split(',');

                // Set the format to the string array.
                requestProperties.Body["formats"] = rawFormats;

            }

            // Check if a key password was specified.
            if ((KeyPassphraseRequired) && (requestProperties != null) && (requestProperties.Body != null) && (requestProperties.Body.ContainsKey("keyPassword")))
            {
                // Prompt for the Key Password.
                NetworkCredential myKeyPass = new("","ThisIsALongPasswordPhrase2022!");
                this.Logger.WriteLine("Ask user for credentials.");

                // Check the provided password.
                if ((myKeyPass != null) && (myKeyPass.SecurePassword.Length > 8))
                {
                    // Set the key format.
                    requestProperties.Body["keyPassword"] = myKeyPass.Password;
                }
            }

            // Get the MFA Caching SSH key.
            HTTPResult webResult = this.ProcessRequest(requestProperties);

            // Check the result.
            if (webResult.IsSuccess)
            {
                // Make sure the data returned is not null and it is JSON.
                if ((webResult.Returned != null) && (webResult.Returned != "") && (webResult.Type.ToLower() == "application/json"))
                {
                    // Web Request was successfull.  Decode the result.
                    mFAObject = new MFAObject(webResult.Returned);
                }

            }
            else
            {
                this.Logger.WriteError(string.Format("Failed to get SSH key(s) ({0}) from:  \r\n\t-->{1}", requestProperties.GetBodyParameter("formats"), requestProperties.Uri.AbsoluteUri));
                this.Logger.WriteError(string.Format("HTTP Response Code ({0}) : Message ({1})", webResult.StatusCode, webResult.StatusMessage));
            }

            // Check the MFAObject.
            if ((mFAObject != null) && (mFAObject.count > 0))
            {
                // Write out information.
                this.Logger.WriteLine(string.Format("Generated Key(s) Count :  {0}", mFAObject.count));
                this.Logger.WriteLine(string.Format("  (UTC) Creation Time  :  {0}", DateTime.UnixEpoch.AddSeconds(mFAObject.creationTime)));
                this.Logger.WriteLine(string.Format("  (UTC) Expiration Time:  {0}", DateTime.UnixEpoch.AddSeconds(mFAObject.expirationTime)));

                // Test the Value.
                if ((mFAObject.value != null) && (mFAObject.value.Count > 0))
                {
                    this.Logger.WriteLine(string.Format("***** SSH Key(s) ***** "));

                    // Loop Count
                    int lc = 0;
                    // Loop over the returned SSH key(s).
                    foreach (SSHKey item in mFAObject.value)
                    {
                        // increment loop count.
                        lc++;

                        // Write output.
                        this.Logger.WriteLine(string.Format(" SSH Key Format ({0})  :  {1}", lc, item.format));
                        this.Logger.WriteLine(string.Format("SSH Key Algorithm ({0}):  {1}\r\n", lc, item.keyAlg));

                    }
                }
            }

            // Return the object.
            return mFAObject;
        }

        public UserDetails GetCurrentUserDetails()
        {
            // Build return object.
            UserDetails userResult = new();

            // Get the request details.
            RequestProperties properties = Users.GetLoggedOnUserDetails();

            // Make the request.
            HTTPResult result = this.ProcessRequest(properties);

            // Check the result
            if ((result != null) && (result.IsSuccess))
            {
                // The result is not null and is successful.
                userResult = JsonSerializer.Deserialize<UserDetails>(result.Returned);
            }

            // Return the result.
            return userResult;
        }
        public bool WriteSSHKeys(string Path, MFAObject Keys)
        {
            // Create the return object.
            bool result = false;

            // Test the path.
            if ((Path != null) && (Path != ""))
            {
                // Path isn't null or blank.  Get the full path.
                string fullPath = System.IO.Path.GetFullPath(Path);

                // Test the full path.
                if ((fullPath != null) && (fullPath != ""))
                {
                    // Full path is not null or blank.  Test full path.
                    // Get the last folder or filename.
                    string fileName = System.IO.Path.GetFileNameWithoutExtension(fullPath);

                    // Get the file extension.
                    string fileExtension = System.IO.Path.GetExtension(fullPath);

                    // Try one level up for the foler and test later.
                    string duPath = System.IO.Path.GetDirectoryName(fullPath);

                    // Test if the path exists.
                    if (System.IO.Directory.Exists(duPath))
                    {
                        // Get the file attributes.
                        FileAttributes fileAttributes = File.GetAttributes(duPath);

                        // Test if the fileName is a folder.
                        if (fileAttributes.HasFlag(FileAttributes.Directory))
                        {
                            //  This is a directory (folder).  Process the SSH key(s).
                            if ((Keys.count > 0) && (Keys.value.Count > 0))
                            {
                                // Public Key
                                if ((Keys.publicKey != null) && (Keys.publicKey != ""))
                                {
                                    // The public key is not null or blank.
                                    string pubFileName = string.Format("{0}-{1}-{2}.{3}", fileName, "PUBLIC-Expires", DateTime.UnixEpoch.AddSeconds(Keys.expirationTime).ToString("yyyy-MM-dd_HHmmss"), "SSH");

                                    // Join the public key filename with the path.
                                    string pubFullPath = System.IO.Path.Combine(duPath, pubFileName);

                                    //Status
                                    this.Logger.WriteLine(string.Format("Writing to file:  \r\n\t-->{0}", pubFullPath));

                                    // Write the file.
                                    System.IO.File.WriteAllText(pubFullPath, Keys.publicKey);

                                }
                                // 1 or more keys exist.
                                foreach (SSHKey key in Keys.value)
                                {
                                    // Test the key.
                                    if ((key != null) && (key.format != null) && (key.format != "") && (key.keyAlg != null) && (key.keyAlg != ""))
                                    {
                                        // Test the private key
                                        if ((key.privateKey != null) && (key.privateKey != ""))
                                        {
                                            // The private key is not null or blank.  Write the file.
                                            string newFileName = string.Format("{0}-{1}.{2}", fileName, key.keyAlg, key.format);

                                            // Join the new filename with the path
                                            string newFullPath = System.IO.Path.Combine(duPath, newFileName);

                                            // Status
                                            this.Logger.WriteLine(string.Format("Writing to file:  \r\n\t-->:{0}", newFullPath));

                                            // Write the file.
                                            System.IO.File.WriteAllText(newFullPath, key.privateKey);

                                            // Status
                                            this.Logger.WriteLine("File Written");
                                        }
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        // The folder path does not exist.
                        this.Logger.WriteError(string.Format("Path NOT Found!  {0}", duPath));
                    }
                }
            }

            // Return the object.
            return result;
        }
        //endRegion Public Methods
    }

    public class HTTPResult
    {
        public bool IsSuccess { get; set; }
        public int StatusCode { get; set; }
        public string StatusMessage { get; set; }
        public string Returned { get; set; }
        public string Type { get; set; }
        public string ErrorDetails { get; set; }

        public HTTPResult()
        {
            this.IsSuccess = false;
            this.StatusCode = 0;
            this.StatusMessage = string.Empty;
            this.Returned = string.Empty;
            this.Type = string.Empty;
            this.ErrorDetails = string.Empty;

        }
    }
}