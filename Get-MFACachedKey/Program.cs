// See https://aka.ms/new-console-template for more information
using Get_MFACachedKey;
using CyberArkPASSCaller;
using CyberArkPASSAPIAuth;
using CyberArkPASSAPIUser;
using System.ComponentModel.Design;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Net;
using System.Security.Cryptography.X509Certificates;

// Set the threading model.
// It is unfortunate but we have to set it to Unknown first.
Thread.CurrentThread.SetApartmentState(ApartmentState.Unknown);
Thread.CurrentThread.SetApartmentState(ApartmentState.STA);

// Specify Exit Codes
Dictionary<int, string> _exitCodes = new Dictionary<int, string>();
_exitCodes.Add(10, "Invalid authentication method specified!");
_exitCodes.Add(20, "");
_exitCodes.Add(30, "A Username and a BLANK Password were given.");
_exitCodes.Add(31, "A BLANK Username and BLANK Password were given with no Client Certificate selected.");
_exitCodes.Add(32, "A BLANK Username and NON blank Password were given.");
_exitCodes.Add(33, "User supplied multiple client authentication certificates.");
_exitCodes.Add(40, "");
_exitCodes.Add(50, "");
_exitCodes.Add(60, "");
_exitCodes.Add(70, "");
_exitCodes.Add(80, "");
_exitCodes.Add(90, "");

// Setup logging
Logging Logger = new Logging();

// Setup command line arguments dictionary, specify Ignore Case.
Dictionary<string, string> cmdArgs = new Dictionary<string, string>(StringComparer.CurrentCultureIgnoreCase);

// Set needed default values.  These will be over written if a command line argument is passed.
cmdArgs.Add("URL", "https://cyberpass.company.com/PasswordVault");
cmdArgs.Add("IgnoreSSL","False");
cmdArgs.Add("ConfigFile","C:\\Engagements\\JesseMcWilliams\\CyberArk_PAS_Exe\\Get-MFACachedKey\\Conf\\DEV1-MFACaching-Config.json");
cmdArgs.Add("LogLevel","Verbose");

LogLevel LoggingLevel = LogLevel.Verbose;

//  Check if there are any command line arguments.
if (args.Length > 0)
{
    // Call Utilities Arguments Parser.
    cmdArgs = Arguments.Parse(args);

    // Check the requested logging level.
    if (cmdArgs.ContainsKey("LogLevel"))
    {
        // Set the desired logging level by calling GetLogLevel in Utilities.
        LoggingLevel = Utilities.GetLogLevel(cmdArgs["LogLevel"]);
        Logger.Level = LoggingLevel;
    }

    // Check if a log file was specified.
    if (cmdArgs.ContainsKey("LogFile"))
    {
        // Set the log file.
        Logger.Path = cmdArgs["LogFile"];
    }

    // Check if Verbose logging has been requested.
    if (LoggingLevel >= LogLevel.Debug)
    {
        Logger.WriteDebug("******************** Parsed Command Line Arguments  ********************");
        // Loop over the arguments.
        foreach (string arg in cmdArgs.Keys)
        {
            // Write the data
            Logger.WriteDebug(string.Format("Key ({0,12}) : Value ({1})", arg, cmdArgs[arg]));
        }
    }
    if (LoggingLevel >= LogLevel.Verbose)
    {
        Logger.WriteVerbose("******************** RAW Command Line Arguments  ********************");
        // Output RAW command line arguments.
        if (args.Length > 0)
        {
            Logger.WriteVerbose(string.Format("Arguments: \r\n\t{0}", string.Join("\r\n\t", args)));
            //Logger.WriteLine(string.Format("Arguments: \r\n\t{0}", string.Join("\r\n\t", args.Select(x => x.Key + "=" + x.Value))));
        }
    }
}

// Check if Help is being called.
if ((cmdArgs.ContainsKey("Help")) || (cmdArgs.ContainsKey("?")))
{
    // Help has been requested.
    Logger.WriteLine("******************** Help ********************", true, true);
    Logger.WriteLine("", true, true);
    Logger.WriteLine("Get-MFACachedKey is a utility to retrieve the MFA Cached Key for use with PSMP.", true, true);
    Logger.WriteLine("This utility can download the SSH key in multiple formats at the same time and save them to.", true, true);
    Logger.WriteLine("separate files.", true, true);
    Logger.WriteLine("You can specify the parameters (switches) on the command line or specify a configuration file.", true, true);
    Logger.WriteLine("", true, true);
    Logger.WriteLine("****************** Switches ******************", true, true);
    Logger.WriteLine("", true, true);
    Logger.WriteLine("-AuthMethod: Values (Cert, User) : Client Authentication Certificate or Username and Yubikey.", true, true);
    Logger.WriteLine("", true, true);
    Logger.WriteLine("     -URL  : This is the fully qualified address.  Include the application name.  Normaly PasswordVault.", true, true);
    Logger.WriteLine("", true, true);
    Logger.WriteLine(" -KeyFormat: Values (PEM, PPK, OpenSSH).  This should match the SSH client you are using.", true, true);
    Logger.WriteLine("             You can specify multiple values by enclosing in '()' and seperated by comma ','.", true, true);
    Logger.WriteLine("", true, true);
    Logger.WriteLine(" -OutFile  : [Optional] Relative or Fully Qualified path to the file to be created.", true, true);
    Logger.WriteLine("                        The key format will be appended to this.", true, true);
    Logger.WriteLine("                        If blank or if the last character is the \\ then the filename will be auto generated.", true, true);
    Logger.WriteLine("", true, true);
    Logger.WriteLine(" -TimeOut  : [Optional] Default 30 seconds.  Specify the value in seconds." , true, true);
    Logger.WriteLine("", true, true);
    Logger.WriteLine("-ThumbPrint: [Optional] This is the thumbprint of the Client Authentication Certificate to use.", true, true);
    Logger.WriteLine("                        If specified AuthMethod is ignored.", true, true);
    Logger.WriteLine("", true, true);
    Logger.WriteLine("-ConfigFile: [Optional] This is a JSON configuration file that hold the options to be used.", true, true);
    Logger.WriteLine("                        All other switches ignored, except LogLevel.", true, true);
    Logger.WriteLine("                        If a configuration file is specified and it doesn't exist a default one will be created.", true, true);
    Logger.WriteLine("", true, true);
    Logger.WriteLine("-LogLevel  : [Optional] Values (None, Error, Warning, Info, Debug, Verbose.)", true, true);
    Logger.WriteLine("", true, true);
    Logger.WriteLine("-LogFile   : [Optional] Relative or Fully Qualified path to a folder or filename.", true, true);
    Logger.WriteLine("                        If blank or if the last character is the \\ then the filename will be auto generated.", true, true);
    Logger.WriteLine("", true, true);
    Logger.WriteLine("****************** Examples ******************", true, true);
    Logger.WriteLine("", true, true);
    Logger.WriteLine(".\\Get-MFACachedKey.exe -URL \"https://epv.company.com/passwordvault\" -AuthMethod User -KeyFormat PPK -OutFile \"My Certs\\MFASSHKey\"", true, true);
    Logger.WriteLine("", true, true);
    Logger.WriteLine(".\\Get-MFACachedKey.exe -URL \"https://epv.company.com/passwordvault\" -AuthMethod User -KeyFormat (PPK, PEM, OpenSSH) -OutFile \"My Certs\\MFASSHKey\"", true, true);
    Logger.WriteLine("", true, true);
    Logger.WriteLine(".\\Get-MFACachedKey.exe -URL \"https://epv.company.com/passwordvault\" -AuthMethod User -KeyFormat (PPK, PEM, OpenSSH) -OutFile \"My Certs\\MFASSHKey\\\"", true, true);
    Logger.WriteLine("", true, true);
    Logger.WriteLine(".\\Get-MFACachedKey.exe -URL \"https://epv.company.com/passwordvault\" -AuthMethod User -KeyFormat (PPK, PEM, OpenSSH)", true, true);
    Logger.WriteLine("", true, true);
    Logger.WriteLine(".\\Get-MFACachedKey.exe -ConfigFile \"C:\\My Files\\Prod_jmcwilliams.json\"", true, true);
    Logger.WriteLine("", true, true);
    Logger.WriteLine(".\\Get-MFACachedKey.exe -ConfigFile \"C:\\My Files\\Prod_jmcwilliams.json\" -LogLevel Verbose", true, true);
    Logger.WriteLine("", true, true);
    // Exit
    Environment.Exit(0);
}

// Create a variable that can be null to hold the configuration file.
string? configurationFile = "";

// Try to get the configuration file name from the command line arguments.  This can be a null value.
cmdArgs.TryGetValue("ConfigFile", out configurationFile);

// Declare the configuration object.  This will be populated by default values if no configuration file is specified.
Config MyConfig = new Config(configurationFile);

// Apply the command line arguments to the current configuration.  A configuration file will be written if specified.
MyConfig.LoadArguments(cmdArgs);

// Apply the log level
LoggingLevel = Utilities.GetLogLevel(MyConfig.LogLevel);
Logger.Level = LoggingLevel;

// Apply the log file.
Logger.Path = MyConfig.LogFile;

Logger.WriteLine("", true);
Logger.WriteLine("**************************************************");
Logger.WriteLine("******************** Starting ********************");

// If Info logging is enabled.  Do Configuration Test.
if (LoggingLevel >= LogLevel.Info)
{
    Logger.WriteInfo("******************** Configuration ********************");
    Logger.WriteInfo(string.Format("Configuration File:  \r\n\t-->{0}", configurationFile));
    Logger.WriteInfo(string.Format("      AuthMethod  :  {0}", MyConfig.AuthMethod));
    Logger.WriteInfo(string.Format("Password Vault URL:  {0}", MyConfig.URL));
    Logger.WriteInfo(string.Format("       KeyFormat  :  {0}", MyConfig.KeyFormat));
    Logger.WriteInfo(string.Format("         OutFile  :  \r\n\t-->{0}", MyConfig.OutFile));
    Logger.WriteInfo(string.Format("      ThumbPrint  :  {0}", MyConfig.ThumbPrint));
    Logger.WriteInfo(string.Format("        LogLevel  :  {0}", MyConfig.LogLevel));
    Logger.WriteInfo(string.Format("         LogFile  :  \r\n\t-->{0}", MyConfig.LogFile));
    Logger.WriteInfo(string.Format("Ignore SSL Errors :  {0}", MyConfig.IgnoreSSL));
    Logger.WriteInfo(string.Format("Request Timeout   :  {0}", MyConfig.RequestTimeOut));
}

// If Verbose logging is enabled.  Do logger test output.
if (LoggingLevel >= LogLevel.Info)
{
    Logger.WriteInfo("******************** Logger Test ********************");
    Logger.WriteLine("Write Line");
    Logger.WriteError("Write Error");
    Logger.WriteWarning("Write Warning");
    Logger.WriteInfo("Write Info");
    Logger.WriteDebug("Write Debug");
    Logger.WriteVerbose("Write Verbose");
}

//region Flow
Logger.WriteLine("************** Get User Credential ****************");
// Create a default network credential.
NetworkCredential userCred = new NetworkCredential();

// Create a default X509 Certificate Collection.
X509Certificate2? userCert = null;

// Create a default Authentication Method.
AuthMethods userAuthMethod = AuthMethods.CyberArk;

// Check the requested authentication method.
if ((MyConfig.AuthMethod.ToLower() == "user") || (MyConfig.AuthMethod.ToLower() == "user:sso"))
{
    // Go to the Auth Token request.  The user will be prompted by the SSO sight for credentials.
    // Set the authentication method.
    userAuthMethod = AuthMethods.SAML;
}
else if ((MyConfig.AuthMethod.ToLower() == "cert") || (MyConfig.AuthMethod.ToLower() == "cert:pkipn"))
{
    // Populate the x509 Certificate Collection with the matching certificate.
    userCert = Utilities.GetCertificate(MyConfig.ThumbPrint);

    // Set the authentication method.
    userAuthMethod = AuthMethods.PKIPN;

}
else if (MyConfig.AuthMethod.ToLower() == "cert:pki")
{
    // Populate the x509 Certificate Collection with the matching certificate
    userCert = Utilities.GetCertificate(MyConfig.ThumbPrint);

    // Set the authentication method.
    userAuthMethod = AuthMethods.PKI;
}
else if (MyConfig.AuthMethod.ToLower() == "prompt:ldap")
{
    // Get the user's credential.
    userCred = Utilities.GetCredential();

    // Use LDAP authentication.
    userAuthMethod = AuthMethods.LDAP;
}
else if (MyConfig.AuthMethod.ToLower() == "prompt:ca")
{
    // Get the user's credential.
    userCred = Utilities.GetCredential();

    // Use CyberArk authentication.
    userAuthMethod = AuthMethods.CyberArk;
}
else
{
    // Invalid Authentication method specified.
    int _errorCode = 10;
    Logger.WriteError(string.Format("Exit Code ({0}) : Message: {1}", _errorCode, _exitCodes[_errorCode]));
    Environment.Exit(_errorCode);
}

Logger.WriteLine("**************** Get Auth Token *****************");

// Create the object to manage the connection with CyberArk.  The constructer needs the base URL.
CyberArkPASS pvwa = new(MyConfig.URL, MyConfig.LogFile, Utilities.GetLogLevel(MyConfig.LogLevel));

// Set the request timeout.
pvwa.RequestTimeout = MyConfig.RequestTimeOut;

// Set the Authentication Method.
pvwa.AuthMethod = userAuthMethod;

// Set ignore SSL if set.
if (MyConfig.IgnoreSSL)
{
    pvwa.IgnoreSSL = MyConfig.IgnoreSSL;
}

// Create a variable to identify if authentication was successfull.
bool isAuthenticated = false;

// Display the the authentication method.
Logger.WriteInfo(string.Format("Authentication Method:  {0}", userAuthMethod));

// Check the given credentials.
if ((userCred != null) && (userCred.UserName == "") && (userAuthMethod == AuthMethods.SAML))
{
    // The user has selected SSO.  No credential needed.
    // Call Authenticate
    isAuthenticated = pvwa.Authenticate(userAuthMethod);
}

else if ((userCred != null) && (userCred.UserName != "") && (userCred.Password.Length > 0))
{
    // The user has supplied a username and password.
    // Set the user credential on the PVWA object.
    pvwa.UserCredential = userCred;

    // Call Authenticate
    isAuthenticated = pvwa.Authenticate(userAuthMethod);
}

else if ((userCred != null) && (userCred.UserName != "") && (userCred.Password.Length == 0))
{
    // The user has supplied a username and a blank password.
    // This is an invalid state.
    int _errorCode = 30;
    Logger.WriteError(string.Format("Exit Code ({0}) : Message: {1}", _errorCode, _exitCodes[_errorCode]));
    Environment.Exit(_errorCode);
}

else if ((userCred != null) && (userCred.UserName == "") && (userCred.Password.Length == 0) && (userCert == null))
{
    // The user has supplied a blank username, a blank password, and no Certificates.
    // This is an invalid state.
    int _errorCode = 31;
    Logger.WriteError(string.Format("Exit Code ({0}) : Message: {1}", _errorCode, _exitCodes[_errorCode]));
    Environment.Exit(_errorCode);
}

else if ((userCred != null) && (userCred.UserName == "") && (userCred.Password.Length == 0) && (userCert != null))
{
    // The user has supplied a Certificate.
    // Set the certificate on the PVWA object.
    pvwa.UserCertificate = userCert;

    // Call Authenticate
    isAuthenticated = pvwa.Authenticate(userAuthMethod);
}

else if ((userCred != null) && (userCred.UserName == "") && (userCred.Password.Length > 0))
{
    // The user has supplied a blank username and a NON blank password.
    // This is an invalid state.
    int _errorCode = 32;
    Logger.WriteError(string.Format("Exit Code ({0}) : Message: {1}", _errorCode, _exitCodes[_errorCode]));
    Environment.Exit(_errorCode);
}

// Check if authentication was successful.
if (isAuthenticated)
{
    Logger.WriteLine("**************** Get User Details *****************");
    UserDetails userDetails = pvwa.GetCurrentUserDetails();
    if (userDetails != null)
    {
        // Output user details.
        Logger.WriteLine(string.Format("Successfully Logged on as user:  {0}", userDetails.UserName));
        Logger.WriteInfo(string.Format("    User Name  :  {0}", userDetails.UserName));
        Logger.WriteInfo(string.Format("Email Address  :  {0}", userDetails.Email));
        Logger.WriteInfo(string.Format("    Last Name  :  {0}", userDetails.LastName));
        Logger.WriteInfo(string.Format("   First Name  :  {0}", userDetails.FirstName));
        Logger.WriteInfo(string.Format("User Location  :  {0}", userDetails.Location));
        Logger.WriteInfo(string.Format("  User Source  :  {0}", userDetails.Source));
        Logger.WriteInfo(string.Format("Expiration Date:  {0}", userDetails.ExpiryDate));
        Logger.WriteInfo(string.Format("   Is Expired  :  {0}", userDetails.Expired));
        Logger.WriteInfo(string.Format("  Is Disabled  :  {0}", userDetails.Disabled));
        Logger.WriteInfo(string.Format(" Is Suspended  :  {0}", userDetails.Suspended));
        Logger.WriteInfo(string.Format("Is Agent User  :  {0}", userDetails.AgentUser));
    }
    Logger.WriteLine("***************** Get SSH Token ******************");

    // Flush cookies.
    pvwa.FlushCookies();

    // This will retrieve an SSH token for MFA caching.  To be used with PSMP connections.
    MFAObject mFAObject = pvwa.GetMFASSHKey(KeyFormat: MyConfig.KeyFormat, KeyPassphraseRequired: MyConfig.PassphraseRequired);

    // Test the MFAObject.
    if ((mFAObject != null) && (mFAObject.count > 0))
    {
        // MFAObject is not null and has at least 1 SSH key.
        Logger.WriteLine("***************** Save SSH Token(s) *****************");
        pvwa.WriteSSHKeys(MyConfig.OutFile, mFAObject);

    }
    else
    {
        Logger.WriteError(string.Format("Failed to retrieve the SSH Key(s)."));
    }

    Logger.WriteLine("****************   Logging Off   *****************");
    pvwa.Logoff();

}

Logger.WriteLine("******************** Finished ********************");
Logger.WriteLine("**************************************************\r\n");
//endregion Flow