using System.ComponentModel;
using System.Diagnostics.Tracing;
using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using System.Net;
using System.Security;
using System.Security.Principal;
using System.Windows.Forms;
//using Windows.Security.Credentials.UI;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;


namespace Get_MFACachedKey
{
    public static class Utilities
    {
        public static string JoinURL(string Path, string ChildPath)
        {
            Path = Path.TrimEnd('/');
            ChildPath = ChildPath.TrimStart('/');
            return string.Format("{0}/{1}", Path, ChildPath);
        }
        public static LogLevel GetLogLevel(string LogLevelName)
        {
            // Convert the Log Level Name into a valid Logging Level.
            switch (LogLevelName.ToLower())
            {
                case "none":
                    return LogLevel.None;
                case "error":
                    return LogLevel.Error;
                case "warning":
                    return LogLevel.Warning;
                case "info":
                    return LogLevel.Info;
                case "information":
                    return LogLevel.Info;
                case "debug":
                    return LogLevel.Debug;
                case "verbose":
                    return LogLevel.Verbose;
                default:
                    Console.BackgroundColor = ConsoleColor.Black;
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Invalid Logging Level Specified.");
                    Console.WriteLine("Valid Values (None, Error, Warning, Info, Debug, Verbose)");
                    Console.WriteLine("Given Logging Level:  {0}", LogLevelName);
                    Console.ResetColor();
                    return LogLevel.Verbose;
            }
        }
        public static NetworkCredential GetCredential()
        {
            // This will prompt the user to enter in a Username and Password.
            
            
            Runspace runSpace = RunspaceFactory.CreateRunspace();
            runSpace.Open();
            Pipeline pipeline = runSpace.CreatePipeline();
            Command cmd = new("Get-Credential");
            pipeline.Commands.Add(cmd);
            var output = pipeline.Invoke();

            // Create the network credential to be returned and return it.
            return new NetworkCredential ("CA_Jesse", "Password22!");
            
        }
        public static X509Certificate2 GetCertificate(string? ThumbPrint)
        {
            const String RSA = "1.2.840.113549.1.1.1";
            const String DSA = "1.2.840.10040.4.1";
            const String ECC = "1.2.840.10045.2.1";

            // Create the return object.
            X509Certificate2 cert = null;

            // Create an empty collection.
            X509Certificate2Collection certs = null;

            // Specify a new certificate store.
            X509Store myStore = new X509Store("My", StoreLocation.CurrentUser);

            // Set the store flags.
            myStore.Open(OpenFlags.ReadOnly|OpenFlags.OpenExistingOnly);

            // Get all the certificates from the store.
            X509Certificate2Collection myCertificates = myStore.Certificates;

            // Filter the certificates for Client Authentication only.
            X509Certificate2Collection clientAuth = myCertificates.Find(X509FindType.FindByApplicationPolicy, "1.3.6.1.5.5.7.3.2", true);

            // If a thumb print is given then get it.
            if ((ThumbPrint != null) && (ThumbPrint != ""))
            {
                // Get the certificate that matches the thumbprint.
                certs = clientAuth.Find(X509FindType.FindByThumbprint, ThumbPrint, true);

                // Get the certificate from the collection.
                cert = certs.FirstOrDefault();

            }
            else
            {
                // Check if the client authentication certificates have been returned.
                if ((clientAuth != null) && (clientAuth.Count > 0))
                {
                    // Check the number of certificates.
                    if (clientAuth.Count == 1)
                    {
                        // Only one certificate.
                        cert = clientAuth.FirstOrDefault();
                    }
                    else
                    {
                        // Open Certificate Picker.
                        certs = X509Certificate2UI.SelectFromCollection(clientAuth, "Client Certificate Selection", "Please choose a certificate", X509SelectionFlag.SingleSelection);

                        // Get the certificate from the collection.
                        cert = certs.FirstOrDefault();
                    }
                }
                
            }

            // Test the certificate.
            if ((cert != null) && (cert.Subject != ""))
            {
                // The certificate is not null or blank.
                // Test if there is a private key.
                if (cert.HasPrivateKey)
                {
                    RSACng myKey = new();
                    CngProvider provider = null;
                    

                    // Get the private key.
                    switch (cert.PublicKey.Oid.Value)
                    {
                        case RSA:
                            // Get the private key.
                            RSA rsaKey = cert.GetRSAPrivateKey();

                            // Cast the RSA object to RSACng object.
                            myKey = (RSACng)rsaKey;

                            // Get the Private Key Provider.
                            provider = myKey.Key.Provider;

                            //myKeyInfo = (CspKeyContainerInfo) rsaKey;
                            break;

                        case DSA:
                            DSA dsaKey = cert.GetDSAPrivateKey();
                            break;

                        case ECC:
                            ECDiffieHellman eccKey = cert.GetECDiffieHellmanPrivateKey();
                            break;
                    }
                    // The certificate has a private key.
                    // Check if the certificate is on a hardware device.
                    //CngKey cp = myKey.Key;

                    if ((provider != null) && (provider.Equals(CngProvider.MicrosoftSmartCardKeyStorageProvider)))
                    {
                        //
                        
                        var stopHere = "";
                    }
                }
                else
                {
                    // Status
                    Console.WriteLine("The Selected Certificate does NOT have a private key!");

                    // Zero out the certificate.
                    cert = null;
                }
            }

            

            // Return object
            return cert;
        }
    }
       
    public static class Arguments
    {
        // Parse command line arguments.
        // This is the character that identifies the parameter name.
        public static char Identifier = '-';
        //  Create a dictionary to hold the arguments
        public static Dictionary<string, string> cmdArgs = new Dictionary<string, string>(StringComparer.CurrentCultureIgnoreCase);
        public static Dictionary<string, string> Parse(string[] args)
        {
            //
            // Create a variable to hold the Key.
            string cmdKey = "";

            // Split the arguments.
            foreach (string arg in args)
            {
                // Check if the key should be set.
                if ((arg.StartsWith('-')) && (cmdKey == ""))
                {
                    // Set the key.
                    cmdKey = arg.Substring(1, arg.Length - 1);
                }
                else if ((arg.StartsWith('-')) && (cmdKey != ""))
                {
                    // The first one is a switch, maybe.
                    cmdArgs.Add(cmdKey, true.ToString());

                    // Set the key.
                    cmdKey = arg.Substring(1, arg.Length - 1);
                }

                // Check for all possible combinations.
                else if ((cmdArgs.Count() > 0) && (!(arg.StartsWith('-'))))
                {
                    // Count is NOT 0 and does NOT start with '-'
                    // This should be the value.
                    if (cmdKey != "")
                    {
                        cmdArgs.Add(cmdKey, arg);

                        // Clear the cmdKey.
                        cmdKey = "";
                    }
                }
                else if ((cmdArgs.Count() > 0) && (arg.StartsWith('-')))
                {
                    // Count is NOT 0 and arg starts with '-'
                    // This should be the key.
                }
                else if ((cmdArgs.Count() == 0) && (!(arg.StartsWith('-'))))
                {
                    // Count is 0 and does NOT start with '-'
                    // This should be the vaule.
                    if (cmdKey != "")
                    {
                        cmdArgs.Add(cmdKey, arg);

                        // Clear the cmdKey.
                        cmdKey = "";
                    }
                }
                else if ((cmdArgs.Count() == 0) && (arg.StartsWith('-')))
                {
                    // Count is 0 and deos start with '-'
                    // This should be the key.
                }
            }
            // Check for a trailing switch.
            if (cmdKey != "")
            {
                cmdArgs.Add(cmdKey, "True");
            }
            return cmdArgs;
        }
    }
}