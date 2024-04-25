using System.Globalization;
using System.Threading.Tasks.Dataflow;
using System.Text.Json;
using System.Runtime.CompilerServices;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;

namespace Get_MFACachedKey
{
    public class Config
    {
        //region Error Codes
        private const int ERROR_BAD_PATH = 0XA0;
        private const int ERROR_FILE_ISSUE = 0XA1;
        private const int ERROR_BAD_FILE_PATH = 0XA2;
        private const int ERROR_FILE_NOTFOUND = 0XA3;
        //endRegion Error Codes
        public string? FilePath { get; set; }
        private Configuration ThisConfig;

        //region Constructors
        public Config()
        {
            // Set the default path.
            string Path = ".\\Conf\\Default-MFACaching-Config.json";

            // Set the path to an absolute / fully qualifed path.
            this.SetPath(Path);

            // Initialize a default configuration object.
            this.ThisConfig = new Configuration();
        }
        public Config(string? Path)
        {
            // Set the path to an absolute / fully qualifed path.
            this.SetPath(Path);

            // Initialize the configuration object.
            this.ThisConfig = new Configuration();

            // Does the file in the path exist?
            if (File.Exists(this.FilePath))
            {
                // The file exists.  Read the file.
                this.Read();
            }
            else if ((this.FilePath != "") && (this.FilePath != null))
            {
                // Create the configuration file.
                this.Write();

                // Exit with success.
                Environment.Exit(0);
            }
        }

        //endRegion Constructors
        
        //region Public Methods
        public void Write()
        {
            // Check if the File Path is blank or null.
            if ((this.FilePath != null) && (this.FilePath != ""))
            {
                //
                Debug.WriteLine("{0} : Serialize Configuration to JSON string.", DateTime.Now.ToString("yyyy/dd/MM hh:mm:ss"));

                // Set WriteIndented to true.
                JsonSerializerOptions options = new()
                {
                    WriteIndented = true
                };

                // Serialize the Configuration into a json string.
                string jsonString = JsonSerializer.Serialize<Configuration>(this.ThisConfig, options);

                Debug.WriteLine("{0} : Configuration Serialized to JSON string.", DateTime.Now.ToString("yyyy/dd/MM hh:mm:ss"));

                // Get the folder path without the filename.
                string folderPath = Path.GetDirectoryName(this.FilePath);

                // Check to see if the specified folder exists.
                if (Path.Exists(folderPath))
                {
                    Debug.WriteLine("{0} : Writing to file:  {1}", DateTime.Now.ToString("yyyy/dd/MM hh:mm:ss"), this.FilePath);

                    // Write the json string to the file.
                    File.WriteAllText(this.FilePath, jsonString);

                    Debug.WriteLine("{0} : Configuration file written.", DateTime.Now.ToString("yyyy/dd/MM hh:mm:ss"));
                }
                else
                {
                    // Set a new console color.
                    Console.BackgroundColor = ConsoleColor.Black;
                    Console.ForegroundColor = ConsoleColor.Yellow;

                    // Write message
                    Console.WriteLine("{0} : WARNING : Destination folder does NOT exist.  \r\n\tPath:  {1}", DateTime.Now.ToString("yyyy/dd/MM hh:mm:ss"), folderPath);

                    // Restore original console colors.
                    Console.ResetColor();

                    // Exit
                    Environment.Exit(ERROR_BAD_PATH);
                }
            }
            else
            {
                // Set a new console color.
                Console.BackgroundColor = ConsoleColor.Black;
                Console.ForegroundColor = ConsoleColor.Yellow;

                // Write message
                Console.WriteLine("{0} : WARNING : File path is NULL or BLANK.  \r\n\tFilePath:  {1}", DateTime.Now.ToString("yyyy/dd/MM hh:mm:ss"), this.FilePath);

                // Restore original console colors.
                Console.ResetColor();

                // Exit
                Environment.Exit(ERROR_BAD_FILE_PATH);
            }
            
            

        }
        public void Read()
        {
            Debug.WriteLine("{0} : Reading Configuration file:  \r\n\t-->{1}", DateTime.Now.ToString("yyyy/dd/MM hh:mm:ss"), this.FilePath);

            // Check to see if the specified file exists.
            if (File.Exists(this.FilePath))
            {
                // Read the configuration from file.
                string jsonString = File.ReadAllText(this.FilePath);
                
                // Verify that the json string is not blank or null.
                if ((jsonString != null) && (jsonString != ""))
                {
                    Debug.WriteLine("{0} : Deserialize JSON string.", DateTime.Now.ToString("yyyy/dd/MM hh:mm:ss"));
                    // Deserialize the json text string.
                    this.ThisConfig = JsonSerializer.Deserialize<Configuration>(jsonString);

                    Console.WriteLine("{0} :  CONFIG : Configuration Imported.", DateTime.Now.ToString("yyyy/dd/MM hh:mm:ss"));
                }
                else
                {
                    // Configuration file is blank?
                    // Set a new console color.
                    Console.BackgroundColor = ConsoleColor.Black;
                    Console.ForegroundColor = ConsoleColor.Yellow;

                    // Write message
                    Console.WriteLine("{0} : WARNING : Configuration is blank or malformed JSON.  \r\n\tFile:  {1}", DateTime.Now.ToString("yyyy/dd/MM hh:mm:ss"), this.FilePath);

                    // Restore original console colors.
                    Console.ResetColor();

                    // Exit
                    Environment.Exit(ERROR_FILE_ISSUE);

                }
                
            }
            else
            {
                // The specified file does not exist.
                // Set a new console color.
                Console.BackgroundColor = ConsoleColor.Black;
                Console.ForegroundColor = ConsoleColor.Yellow;

                // Write message
                Console.WriteLine("{0} : WARNING : Configuration file does NOT exist.  \r\n\tFile:  {1}", DateTime.Now.ToString("yyyy/dd/MM hh:mm:ss"), this.FilePath);

                // Restore original console colors
                Console.ResetColor();

                // Exit
                Environment.Exit(ERROR_FILE_NOTFOUND);
            }

            

        }

        public string AuthMethod
        {
            get {
                return this.ThisConfig.AuthMethod["Value"];
            }
            set {
                this.ThisConfig.AuthMethod["Value"] = value;
            }
            
        }
        public string URL
        {
            get {
                return this.ThisConfig.URL["Value"];
            }
            set {
                this.ThisConfig.URL["Value"] = value;
            }
            
        }
        public string KeyFormat
        {
            get {
                return this.ThisConfig.KeyFormat["Value"];
            }
            set {
                this.ThisConfig.KeyFormat["Value"] = value;
            }
            
        }
        public bool PassphraseRequired
        {
            get
            {
                bool result = false;

                // Get the value from the configuration object.
                System.Text.Json.JsonElement pprValue = this.ThisConfig.PassphraseRequired["Value"];

                // Get the Value Kind.
                result = pprValue.GetBoolean();

                return result;
            }
            set
            {
                this.ThisConfig.PassphraseRequired["Value"] = value;
            }

        }
        public string OutFile
        {
            get {
                return this.ThisConfig.OutFile["Value"];
            }
            set {
                this.ThisConfig.OutFile["Value"] = value;
            }
            
        }
        public string LogLevel
        {
            get {
                return this.ThisConfig.LogLevel["Value"];
            }
            set {
                this.ThisConfig.LogLevel["Value"] = value;
            }
            
        }
        public string LogFile
        {
            get {
                return this.ThisConfig.LogFile["Value"];
            }
            set {
                this.ThisConfig.LogFile["Value"] = value;
            }
            
        }
        
        public int RequestTimeOut
        {
            get {
                return this.ThisConfig.RequestTimeOut;
            }
            set {
                this.ThisConfig.RequestTimeOut = value;
            }
            
        }
        public string ThumbPrint
        {
            get {
                return this.ThisConfig.ThumbPrint["Value"];
            }
            set {
                this.ThisConfig.ThumbPrint["Value"] = value;
            }
            
        }
        public bool IgnoreSSL
        {
            get {
                return this.ThisConfig.IgnoreSSL;
            }
            set {
                this.ThisConfig.IgnoreSSL = value;
            }
            
        }
        public void LoadArguments (Dictionary<string, string> Arguments)
        {
            // Loop over the provided arguments and assign them to this configuration.
            foreach (string argKey in Arguments.Keys)
            {
                // Choose the parameter.
                switch (argKey.ToLower())
                {
                    case "authmethod":
                    {
                        this.AuthMethod = Arguments[argKey];
                        break;
                    }
                    case "url":
                    {
                        this.URL = Arguments[argKey];
                        break;
                    }
                    case "keyformat":
                    {
                        this.KeyFormat = Arguments[argKey];
                        break;
                    }
                    case "PassphraseRequired":
                        {
                            this.KeyFormat = Arguments[argKey];
                            break;
                        }
                    case "outfile":
                    {
                        this.OutFile = Arguments[argKey];
                        break;
                    }
                    case "thumbprint":
                    {
                        this.ThumbPrint = Arguments[argKey];
                        break;
                    }
                    case "loglevel":
                    {
                        this.LogLevel = Arguments[argKey];
                        break;
                    }
                    case "logfile":
                    {
                        this.LogFile = Arguments[argKey];
                        break;
                    }
                    case "ignoressl":
                    {
                        bool ignoreSSL = false;
                        if (Boolean.TryParse(Arguments[argKey], out ignoreSSL))
                        {
                            this.IgnoreSSL = ignoreSSL;
                        }
                        break;
                    }
                    case "timeout":
                    {
                        int timeOut = 30;
                        if (Int32.TryParse(Arguments[argKey], out timeOut))
                        {
                            this.RequestTimeOut = timeOut;
                        }
                        break;
                    }
                }
            }

            // Try writing the configuration
            if ((this.FilePath != null) && (this.FilePath != ""))
            {
                this.Write();
            }
        }
        //endRegion Public Methods

        //region Private Methods
        private void SetPath (string? Path)
        {
            // Check the path attribute.
            if ((Path == null) || (Path == ""))
            {
                this.FilePath = "";
            }
            else
            {
                this.FilePath = System.IO.Path.GetFullPath(Path);
            }
        }
        //endRegion Private Methods
    }

    public class Configuration
    {
        //region Properties
        public Dictionary<string,string> AuthMethod { get; set; }
        public Dictionary<string,string> URL { get; set; }
        public Dictionary<string,string> KeyFormat { get; set; }
        public Dictionary<string, dynamic> PassphraseRequired { get; set; }
        public Dictionary<string,string> OutFile { get; set; }
        public Dictionary<string,string> ThumbPrint { get; set; }
        public Dictionary<string,string> LogLevel { get; set; }
        public Dictionary<string,string> LogFile { get; set; }
        public bool IgnoreSSL { get; set; }
        public int RequestTimeOut { get; set; }
        //endRegion Properties

        //region Constructors
        public Configuration()
        {
            // Default constructor.
            // Initialize all variables to their default values.
            // Initialize AuthMethod.
            this.AuthMethod = new Dictionary<string, string>();
            this.AuthMethod.Add("Value","Cert");
            this.AuthMethod.Add("Note","This should be User or Cert.");
            this.AuthMethod.Add("User","Use Username and Yubikey.");
            this.AuthMethod.Add("Cert","Use Client Authentication Certificate.");
            this.AuthMethod.Add("Example","User");

            // Initialize URL.
            this.URL = new Dictionary<string, string>();
            this.URL.Add("Value","");
            this.URL.Add("Note","This should be a fully qualified domain name.  Include the Application Name.");
            this.URL.Add("Example","https://epv.company.com/PasswordVault");

            // Initialize Key Format.
            this.KeyFormat = new Dictionary<string, string>();
            this.KeyFormat.Add("Value","(PPK, PEM, OpenSSH)");
            this.KeyFormat.Add("Note","This the SSH key file format to download.  Valid Values: PPK, PEM, OpenSSH");
            this.KeyFormat.Add("Example","PPK");
            this.KeyFormat.Add("Note2","For multiple file types seperate them with comma (,)");
            this.KeyFormat.Add("Example2","PPK,PEM");

            // Initialize Passphrase Required.
            this.PassphraseRequired = new Dictionary<string, dynamic>();
            this.PassphraseRequired.Add("Value", false);
            this.PassphraseRequired.Add("Note", "If a Key Passphrase is required set it to true.");
            this.PassphraseRequired.Add("Example", true);
            
            // Initialize Out File.
            this.OutFile = new Dictionary<string, string>();
            this.OutFile.Add("Value","");
            this.OutFile.Add("Note","Please use a fully qualified path and filename.  Do not include a file extension, it will be appended based on the Key Format.");
            this.OutFile.Add("Warning","The back slash needs to be doubled to avoid issues with the JSON file.(\\)");
            this.OutFile.Add("Example","C:\\Temp\\My_SSH_Key");

            // Initialize Thumbprint.
            this.ThumbPrint = new Dictionary<string, string>();
            this.ThumbPrint.Add("Value","");
            this.ThumbPrint.Add("Note","This should be the thumbprint of the certificate to be used.  It needs to be stored on your YubiKey.");
            this.ThumbPrint.Add("Example","1783479e4888ce0fb0910eab691727d418e1ee82");

            // Initialize LogLevel.
            this.LogLevel = new Dictionary<string, string>();
            this.LogLevel.Add("Value","None");
            this.LogLevel.Add("Note","This should be one of the following values; None, Error, Warning, Info, Debug, Verbose.");
            this.LogLevel.Add("Example","None");

            // Initialize LogFile.
            this.LogFile = new Dictionary<string, string>();
            this.LogFile.Add("Value","");
            this.LogFile.Add("Note","This should be a relative or fully qualified path.  Leave blank for none.");
            this.LogFile.Add("Example","Logs\\My_LogFile.txt");

            // Set default values for Request Timeout and IgnoreSSL.
            this.RequestTimeOut = 30;
            this.IgnoreSSL = false;
        }
        //endRegion Constructors

    }
}