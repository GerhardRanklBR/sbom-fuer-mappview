using System.Dynamic;
using System.Runtime.InteropServices;

namespace ConsoleSBOM
{
    public class Args
    {

        const int NECESSARYARGS = 4;
        const int OPTIONALARGS = 5;
        public Args(string[] args)
        {
            ErrorHandling(args);
            if (args[0] == "/h")
            {
                return;
            }
            Seperator = ";";
            OptionalParameter(args);
            PathLibraries = Path.GetFullPath(args[0]);
            FileType = args[1];
            FileName = args[2];
            PathOutput = Path.GetFullPath(args[3]);
            DirectoryErrorHandler();
        }

        public static string PathLibraries { get; private set; } = string.Empty;
        public static string FileType { get; private set; } = string.Empty;
        public static string FileName { get; private set; } = string.Empty;
        public static string PathOutput { get; private set; } = string.Empty;
        public static string PathSpdxHeader { get; private set; } = string.Empty;
        public static string Seperator { get; private set; } = string.Empty;
        public static bool Log { get; private set; }
        public static bool LogFile { get; private set; }
        public static bool Add { get; private set; }
        public static bool DarkMode { get; private set; }


        static void OptionalParameter(string[] input)
        {
            for (int i = NECESSARYARGS; i < input.Length; i++)
            {
                if (input[i] == "log")
                    Log = true;

                if (input[i] == "logfile")
                {
                    LogFile = true;
                    Log = true;
                }

                if (input[i] == "add")
                    Add = true;

                if (input[i] == ",")
                    Seperator = ",";

                if (input[i] == "dark")
                    DarkMode = true;

                if (File.Exists(input[i]))
                    PathSpdxHeader = Path.GetFullPath(input[i]);
            }
        }

        static void PrintHelp()
        {
            Console.WriteLine("----------------------------------------------------------------------------------------------------------");
            Console.WriteLine("The first arg should be the complete filepath to the libaries");
            Console.WriteLine("The second should be the filetype of the file (\"csv\", \"xmll\", \"html\", \"all\")");
            Console.WriteLine("The third value should be the output filename");
            Console.WriteLine("The fourth arg should be the full filepath to the directory, where the new file should end up");
            Console.WriteLine("[Should be the filepath to a sbom.json header formated in a specific way]");
            Console.WriteLine("[Should be \"log\" if a log should be provided and \"logfile\" if the log should be in a file instead]");
            Console.WriteLine("[Should be \"add\" if the new csv should be added at the end of the old one]");
            Console.WriteLine("[Should be a \",\" if the csv should use , as seperators");
            Console.WriteLine("[Should be \"dark\" if the html table should be in dark mode]");
            Console.WriteLine("Note: The args in [] are interchangeable with another, the order doesn't matter");
            Console.WriteLine("----------------------------------------------------------------------------------------------------------");
        }

        static void ErrorHandling(string[] args)
        {
            if (args.Length == 0)
                throw new Exception("Not enough parameter");

            if (args[0] == "/h")
            {
                PrintHelp();
                return;
            }

            if (args.Length <= NECESSARYARGS)
                throw new Exception("Not enough parameter");
        }

        static void DirectoryErrorHandler()
        {
            if (!Directory.Exists(PathLibraries) || !Directory.Exists(PathOutput))
                throw new Exception("The directory doesn't exist");

            if (FileType == "all" || FileType == "spdx")
            {
                if (!File.Exists(PathSpdxHeader))
                    throw new Exception("Spdx path doesn't exist");
            }
        }
    }
}