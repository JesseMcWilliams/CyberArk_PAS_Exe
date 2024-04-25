using System.ComponentModel;
using System.Globalization;
using System.Text;

namespace Get_MFACachedKey
{
    public class Logging
    {
        public string? Path { get; set; }
        public LogLevel Level { get; set; }
        private static ReaderWriterLockSlim _readWriteLock = new ReaderWriterLockSlim();

        public Logging()
        {
            // Default Constructor
            string Path = "";
            this.SetPath(Path);
            this.Level = LogLevel.None;
        }
        public Logging(string? Path)
        {
            // Path Constructor
            this.SetPath(Path);
            this.Level = LogLevel.None;
        }
        public Logging(string? Path, LogLevel Level)
        {
            // Path & Level Constructor
            this.SetPath(Path);
            this.Level = Level;
        }
        public Logging(LogLevel Level)
        {
            // Default Constructor
            string Path = "";
            this.SetPath(Path);
            this.Level = Level;
        }
        private void SetPath(string? Path)
        {
            // Check the path.
            if ((Path == null) || (Path == ""))
            {
                Path = "";
            }
            else
            {
                this.Path = System.IO.Path.GetFullPath(Path);
            }

        }
        private void Write(string Message, LogLevel Level, bool Bare = false, bool ConsoleOnly = false)
        {
            // Write output.
            // Build the line to write.  Choose Bare or not.
            string lineToWrite = "";
            if (Bare)
            {
                lineToWrite = Message;
            }
            else
            {
                lineToWrite = string.Format("{0} : {1,7} : {2}", DateTime.Now.ToString("yyyy/dd/MM hh:mm:ss"), Level, Message);
            }

            // Write the string to the console.
            this.WriteConsole(lineToWrite, Level);

            // Write to the file if not Console Only.
            this.WriteFile(lineToWrite);

        }
        private void WriteConsole(string Message, LogLevel Level)
        {
            // Set the output color and write to the console.
            // Set a new console color based on the logging level.
            if (Level == LogLevel.Error)
            {
                Console.BackgroundColor = ConsoleColor.Black;
                Console.ForegroundColor = ConsoleColor.Red;
            }
            else if (Level == LogLevel.Warning)
            {
                Console.BackgroundColor = ConsoleColor.Black;
                Console.ForegroundColor = ConsoleColor.Yellow;
            }
            else if (Level == LogLevel.Info)
            {
                Console.BackgroundColor = ConsoleColor.Black;
                Console.ForegroundColor = ConsoleColor.Green;
            }
            else if (Level == LogLevel.Debug)
            {
                Console.BackgroundColor = ConsoleColor.Black;
                Console.ForegroundColor = ConsoleColor.Blue;
            }
            else if (Level == LogLevel.Verbose)
            {
                Console.BackgroundColor = ConsoleColor.Black;
                Console.ForegroundColor = ConsoleColor.DarkBlue;
            }

            // Write the message to the console.
            Console.WriteLine(Message);

            // Restore original console colors.
            Console.ResetColor();
        }
        private void WriteFile(string Message)
        {
            // Test the path variable to make sure it is not null.
            if ((this.Path != null) && (this.Path != ""))
            {
                // Test the provided path.  Get the full path.
                string fullPath = System.IO.Path.GetFullPath(this.Path);

                // Get the path without filename.
                string duPath = System.IO.Path.GetDirectoryName(fullPath);

                // Test the full path.
                if ((duPath != null) && (duPath != ""))
                {
                    // The full path is not null and it is not blank.  Test if it exists.
                    if (System.IO.Path.Exists(duPath))
                    {
                        // The full path exists. Write to the file.
                        this.WriteData(Message, this.Path);
                    }
                    else
                    {
                        // The path does not exist.
                        Console.WriteLine(string.Format("The log file path does NOT exist!\r\n\t-->{0}", duPath));
                    }
                }
            }
        }
        private void WriteData(string dataWh, string filePath, bool NewLine = true)
        {
            // Create the write lock.
            _readWriteLock.EnterWriteLock();

            // Use a try block to perform the write operation.
            try
            {
                // If NewLine is true add a new line to the end of the string.
                if (NewLine)
                {
                    // Add a New Line to the string.
                    dataWh += "\r\n";
                }

                // Use a using statement to cleanup after the write is done.
                using (var fs = new FileStream(filePath, FileMode.OpenOrCreate, FileAccess.ReadWrite))
                {
                    // Create a byte array of the message data to be written.
                    byte[] dataAsByteArray = new UTF8Encoding(true).GetBytes(dataWh);

                    // Seek to the end of the file to append the data.
                    fs.Seek(0, SeekOrigin.End);

                    // Write the data to the file.
                    fs.Write(dataAsByteArray, 0, dataWh.Length);
                }
            }
            finally
            {
                // Remove the write lock.
                _readWriteLock.ExitWriteLock();
            }
        }
        public void WriteLine(string Message, bool Bare = false, bool ConsoleOnly = false)
        {
            // Always write.
            this.Write(Message, LogLevel.None, Bare, ConsoleOnly);
        }
        public void WriteError(string Message, bool Bare = false, bool ConsoleOnly = false)
        {
            // Write Error.
            if (this.Level >= LogLevel.Error)
            {
                this.Write(Message, LogLevel.Error, Bare, ConsoleOnly);
            }

        }
        public void WriteWarning(string Message, bool Bare = false, bool ConsoleOnly = false)
        {
            // Write Warning.
            if (this.Level >= LogLevel.Warning)
            {
                this.Write(Message, LogLevel.Warning, Bare, ConsoleOnly);
            }
        }
        public void WriteInfo(string Message, bool Bare = false, bool ConsoleOnly = false)
        {
            // Write Informational.
            if (this.Level >= LogLevel.Info)
            {
                this.Write(Message, LogLevel.Info, Bare, ConsoleOnly);
            }
        }
        public void WriteDebug(string Message, bool Bare = false, bool ConsoleOnly = false)
        {
            // Write Debug.
            if (this.Level >= LogLevel.Debug)
            {
                this.Write(Message, LogLevel.Debug, Bare, ConsoleOnly);
            }
        }
        public void WriteVerbose(string Message, bool Bare = false, bool ConsoleOnly = false)
        {
            // Write Verbose.
            if (this.Level >= LogLevel.Verbose)
            {
                this.Write(Message, LogLevel.Verbose, Bare, ConsoleOnly);
            }
        }
    }
    public enum LogLevel
    {
        [Description("None")]
        None = 0,
        [Description("Error")]
        Error = 1,
        [Description("Warning")]
        Warning = 2,
        [Description("Info")]
        Info = 3,
        [Description("Debug")]
        Debug = 4,
        [Description("Verbose")]
        Verbose = 5
    }
}