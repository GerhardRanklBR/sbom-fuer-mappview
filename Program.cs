using System;
using System.IO;
using System.Net;
using System.Text;
using System.Collections.Generic;
using System.Linq;
namespace ConsoleSBOM
{
    public class Program
    {
        const string BOOTSTRAP = "<link rel=\"stylesheet\" href=\"https://cdn.jsdelivr.net/npm/bootstrap@4.4.1/dist/css/bootstrap.min.css\" integrity=\"sha384-Vkoo8x4CGsO3+Hhxv8T/Q5PaXtkKtu6ug5TOeNV6gBiFeWPGFN9MuhOf23Q9Ifjh\" crossorigin=\"anonymous\">";
        const string JQUERY = "<script src=\"https://code.jquery.com/jquery-3.4.1.slim.min.js\" integrity=\"sha384-J6qa4849blE2+poT4WnyKhv5vZF5SrPo0iEjwBvKU7imGFAV0wwj1yYfoRSJoZ+n\" crossorigin=\"anonymous\" defer></script>";
        const string JSDELIVRPOPPER = "<script src=\"https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.min.js\" integrity=\"sha384-Q6E9RHvbIyZFJoft+2mJbHaEWldlvI9IOYy5n3zV9zzTtmI3UksdQRVvoxMfooAo\" crossorigin=\"anonymous\" defer></script>";
        const string JSDELIVRBOOTSTRAP = "<script src=\"https://cdn.jsdelivr.net/npm/bootstrap@4.4.1/dist/js/bootstrap.min.js\" integrity=\"sha384-wfSDF2E50Y2D1uUdj0O3uMBJnjuUD4Ih7YwaYd1iqfktj0Uod8GCExl3Og8ifwB6\" crossorigin=\"anonymous\" defer></script>";

        public static List<string[]> libraries = new List<string[]>();

        static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                if (args[0] != "/h")
                {
                    if (args.Length >= 4)
                    {
                        if (args[0][1] != ':')
                        {
                            args[0] = Path.GetFullPath(args[0]);
                        }
                        if (args[3][1] != ':')
                        {
                            args[3] = Path.GetFullPath(args[3]);
                        }
                        if (Directory.Exists(args[0]) && Directory.Exists(args[3]))
                        {
                            string pathLibraries = args[0];
                            string filetype = args[1];
                            string filename = args[2];
                            string pathOutput = args[3];
                            string spdxPath;

                            bool[] optArgsBool = OptionalParameter(args, out spdxPath);

                            spdxPath = Path.GetFullPath(spdxPath);

                            if (filetype == "all" || filetype == "spdx" && !File.Exists(spdxPath))
                            {
                                throw new Exception("Spdx path doesn't exist");
                            }

                            string seperator = ";";
                            if (optArgsBool[3])
                                seperator = ",";

                            string lightOrDarkTable = "";

                            if (optArgsBool[4])
                                lightOrDarkTable = "table-dark";

                            Sbom[] sbom;

                            string[] directories = FindLicensesFolders(pathLibraries);

                            bool addToFile = optArgsBool[2];

                            foreach (string directory in directories)
                            {
                                sbom = CreateSbomList(directory, optArgsBool[0], optArgsBool[1], pathOutput, addToFile).ToArray();

                                if (addToFile)
                                {
                                    if (filetype == "csv" || filetype == "all")
                                    {
                                        string[] csv;
                                        string path = Path.Combine(pathOutput, filename + ".csv");
                                        if (File.Exists(path))
                                        {
                                            csv = File.ReadAllLines(Path.Combine(pathOutput, filename + ".csv"));
                                            ConvertToCsv(filename, sbom, pathOutput, csv.Length, seperator, false);
                                        }
                                    }

                                    if (filetype == "html" || filetype == "all")
                                    {
                                        string path = Path.Combine(pathOutput, filename + ".html");
                                        if (File.Exists(path))
                                        {
                                            ConvertToHtml(filename, sbom, pathOutput, lightOrDarkTable, false);
                                        }
                                    }

                                    if (filetype == "spdx" || filetype == "all")
                                    {
                                        string path = Path.Combine(pathOutput, filename + ".json");
                                        if (File.Exists(path))
                                        {
                                            ConvertToSpdx(filename, sbom, pathOutput, spdxPath, false);
                                        }
                                    }
                                }
                                else
                                {
                                    if (filetype == "csv")
                                        ConvertToCsv(filename, sbom, pathOutput, 1, seperator, true);
                                    if (filetype == "html")
                                        ConvertToHtml(filename, sbom, pathOutput, lightOrDarkTable, true);
                                    if (filetype == "spdx")
                                        ConvertToSpdx(filename, sbom, pathOutput, spdxPath, true);
                                    if (filetype == "all" && !addToFile)
                                    {
                                        ConvertToCsv(filename, sbom, pathOutput, 1, seperator, true);
                                        ConvertToHtml(filename, sbom, pathOutput, lightOrDarkTable, true);
                                        ConvertToSpdx(filename, sbom, pathOutput, spdxPath, true);
                                    }
                                }

                                addToFile = directories.Length > 1;
                            }

                            Console.WriteLine("Done");

                        }
                        else
                        {
                            throw new Exception("The directory doesn't exist");
                        }
                    }
                    else
                    {
                        throw new Exception("Not all args were provided");
                    }
                }
                else // /h
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
            }
            else
            {
                throw new Exception("Not enough parameter");
            }
        }

        static bool[] OptionalParameter(string[] input, out string spdxPath)
        {
            bool[] output = new bool[6];
            spdxPath = "";

            for (int i = 4; i < input.Length; i++)
            {
                if (input[i] == "log")
                    output[0] = true;

                if (input[i] == "logfile")
                {
                    output[0] = true;
                    output[1] = true;
                }

                if (input[i] == "add")
                    output[2] = true;

                if (input[i] == ",")
                    output[3] = true;

                if (input[i] == "dark")
                    output[4] = true;

                if (File.Exists(input[i]))
                    spdxPath = input[i];
            }

            return output;
        }

        static Sbom CreateSbom(string directory)
        {
            Sbom output = new Sbom();

            output.Version = VersionCreator(Path.Combine(directory, "VERSION"));
            output.SourceOfLicense = UrlCreator(Path.Combine(directory, "lic-src.url"))[0];
            output.LicenseType = LicenseTypeCreator(Path.Combine(directory, "LICENSETYPE"));
            string[] name = directory.Split(new char[] { '/', '\\' });
            output.Name = name[name.Length - 1];
            output.SourceOfCode = UrlCreator(Path.Combine(directory, "lic-src.url"))[1];
            output.Purl = PurlCreator(Path.Combine(directory, "PURL"));
            output.License = LicenseCreator(Path.Combine(directory, "LICENSE"));

            return output;
        }

        public static List<Sbom> CreateSbomList(string parentDirectory, bool createLog, bool logFile, string outputLoc, bool multipleLicenses)
        {
            string[] directories = FindFoldersWithLicenses(parentDirectory);

            List<Sbom> result = new List<Sbom>();

            for (int i = 0; i < directories.Length; i++)
            {
                Sbom sbomToAdd = CreateSbom(directories[i]);

                if (!CheckRepeatingLibrary(sbomToAdd))
                    result.Add(sbomToAdd);
            }

            if (createLog)
                CreateLog(result.ToArray(), logFile, outputLoc, multipleLicenses);

            return result;
        }

        public static bool CheckRepeatingLibrary(Sbom sbomToAdd)
        {
            string[] tmp = { sbomToAdd.Name, sbomToAdd.Version + "" };

            foreach (string[] library in libraries)
            {
                if (library[0] == tmp[0] && library[1] == tmp[1])
                {
                    return true;
                }
            }

            libraries.Add(tmp);
            return false;
        }

        public static string[] UrlCreator(string directory)
        {
            string[] output = new string[2];
            if (File.Exists(directory))
            {
                string[] lines = File.ReadAllLines(directory);
                string[] splitLine = lines[4].Split('=');

                output[0] = splitLine[splitLine.Length - 1];

                string[] splitUrl = splitLine[splitLine.Length - 1].Split('/');
                splitUrl[splitUrl.Length - 1] = String.Empty;

                foreach (string word in splitUrl)
                {
                    output[1] += "/" + word;
                }
                output[1] = output[1].Trim('/');
            }
            else
            {
                output[0] = String.Empty;
                output[1] = String.Empty;
            }

            return output;
        }

        public static string[] FindLicensesFolders(string directory)
        {
            List<string> licensesFolders = new List<string>();

            if (Directory.Exists(directory))
            {
                foreach (string dir in Directory.GetDirectories(directory, "Licenses", SearchOption.AllDirectories))
                {
                    licensesFolders.Add(dir);
                }
            }

            return licensesFolders.ToArray();
        }

        public static string[] FindFoldersWithLicenses(string directory)
        {
            List<string> licensesFolders = new List<string>();

            if (Directory.Exists(directory))
            {
                foreach (string file in Directory.GetFiles(directory, "LICENSE", SearchOption.AllDirectories))
                {
                    licensesFolders.Add(Path.GetDirectoryName(file)!);
                }
            }

            return licensesFolders.ToArray();
        }

        public static string LicenseTypeCreator(string directory)
        {
            if (File.Exists(directory))
            {
                return File.ReadAllText(directory);
            }
            else
            {
                return String.Empty;
            }
        }

        public static string[] LicenseCreator(string directory)
        {
            if (File.Exists(directory))
            {
                return File.ReadAllLines(directory);
            }
            else
            {
                return new string[1];
            }
        }

        static string VersionCreator(string directory)
        {
            if (File.Exists(directory))
            {
                return File.ReadAllLines(directory)[0];
            }
            else
            {
                return String.Empty;
            }
        }

        static string PurlCreator(string directory)
        {
            if (File.Exists(directory))
            {
                return File.ReadAllText(directory);
            }
            else
            {
                return String.Empty;
            }
        }

        static void CreateLog(Sbom[] sbom, bool logFile, string fileName, bool multipleLicenses)
        {
            DeleteFile(Path.Combine(fileName, "log.txt"), logFile && !multipleLicenses);

            for (int i = 0; i < sbom.Length; i++)
            {
                string name = sbom[i].Name;

                if (!logFile)
                {
                    if (String.IsNullOrEmpty(sbom[i].Version))
                        throw new Exception($"There is no Version in {name}");
                    if (String.IsNullOrEmpty(sbom[i].SourceOfCode))
                        throw new Exception($"There is no Url in {name}");
                    if (String.IsNullOrEmpty(sbom[i].LicenseType))
                        throw new Exception($"There is no Licensetype in {name}");
                    if (sbom[i].License.Length == 1)
                        throw new Exception($"There is no Licensetext in {name}");
                    if (String.IsNullOrEmpty(sbom[i].Purl))
                        throw new Exception($"There is no Purl in {name}");
                }
                else
                {
                    using (StreamWriter sw = new StreamWriter(Path.Combine(fileName, "log.txt"), true))
                    {
                        if (String.IsNullOrEmpty(sbom[i].Version))
                            sw.WriteLine($"There is no Version in {name}");
                        if (String.IsNullOrEmpty(sbom[i].SourceOfCode))
                            sw.WriteLine($"There is no Url in {name}");
                        if (String.IsNullOrEmpty(sbom[i].LicenseType))
                            sw.WriteLine($"There is no Licensetype in {name}");
                        if (sbom[i].License.Length == 1)
                            sw.WriteLine($"There is no Licensetext in {name}");
                        if (String.IsNullOrEmpty(sbom[i].Purl))
                            sw.WriteLine($"There is no Purl in {name}");
                    }
                }
            }
        }

        static void ConvertToSpdx(string filename, Sbom[] sbom, string directory, string headerFile, bool newFile)
        {
            filename = Path.Combine(directory, filename + ".json");

            string[] header;

            if (newFile)
            {
                header = File.ReadAllLines(headerFile);
                header[7] = $"      \"timestamp\": \"{DateTime.UtcNow:yyyy-MM-ddTHH:mm:ssZ}\",";
                header[header.Length - 2] += ",";
                header[header.Length - 1] = "  \"components\": [";
            }
            else
            {
                header = File.ReadAllLines(filename);
                Array.Resize(ref header, header.Length - 2);
            }

            using (StreamWriter writer = new StreamWriter(filename, !newFile))
            {

                foreach (string line in header)
                {
                    writer.WriteLine(line);
                }
                for (int i = 0; i < sbom.Length; i++)
                {
                    writer.WriteLine(newFile ? "" : "   ,");
                    writer.WriteLine("    {");
                    writer.WriteLine("      \"type\": \"library\",");
                    writer.WriteLine($"      \"name\": \"{sbom[i].Name}\",");
                    writer.WriteLine($"      \"version\": \"{sbom[i].Version}\",");
                    writer.WriteLine("      \"licenses\": [");
                    writer.WriteLine("        {");
                    writer.WriteLine("          \"license\": {");
                    writer.WriteLine($"            \"id\": \"{sbom[i].LicenseType}\",");
                    writer.WriteLine($"            \"url\": \"{sbom[i].SourceOfLicense}\"");
                    writer.WriteLine("          }");
                    writer.WriteLine("        }");
                    writer.WriteLine("      ],");
                    writer.WriteLine($"      \"purl\": \"{sbom[i].Purl}\"");
                    writer.WriteLine("    }");
                    newFile = false;
                }

                writer.WriteLine("  ]");
                writer.WriteLine("}");

            }
        }

        static void ConvertToCsv(string filename, Sbom[] sbom, string directory, int length, string seperator, bool newFile)
        {
            filename = Path.Combine(directory, filename + ".csv");

            using (StreamWriter writer = new StreamWriter(filename, !newFile))
            {
                if (newFile)
                {
                    writer.WriteLine($"0{seperator}Name{seperator}LicenseExpressions{seperator}Source of License{seperator}Version{seperator}Source of Code{seperator}Purl{seperator}");
                }

                for (int i = 0; i < sbom.Length; i++)
                {
                    writer.Write((i + length) + seperator);
                    writer.Write(sbom[i].Name + seperator);
                    writer.Write(sbom[i].LicenseType + seperator);
                    writer.Write(sbom[i].SourceOfLicense + seperator);
                    writer.Write(sbom[i].Version + seperator);
                    writer.Write(sbom[i].SourceOfCode + seperator);
                    writer.Write(sbom[i].Purl + seperator);
                    writer.WriteLine();
                }

            }
        }

        static void ConvertToHtml(string filename, Sbom[] sbom, string directory, string lightOrDarkTable, bool newFile)
        {
            filename = Path.Combine(directory, filename + ".html");
            using (StreamWriter writer = new StreamWriter(filename, !newFile))
            {
                bool darkmode = lightOrDarkTable == "table-dark";
                string color = darkmode ? "white" : "black";
                if (newFile) // Print HTML Header
                {
                    writer.WriteLine("<!DOCTYPE html>");
                    writer.WriteLine("<html>");
                    writer.WriteLine("<head>");
                    writer.WriteLine("<style>");
                    writer.WriteLine("table {border:1px solid black;}");
                    writer.WriteLine("th, td {border:1px solid black;}");
                    writer.WriteLine("</style>");
                    writer.WriteLine(BOOTSTRAP);
                    writer.WriteLine(JQUERY);
                    writer.WriteLine(JSDELIVRPOPPER);
                    writer.WriteLine(JSDELIVRBOOTSTRAP);
                    writer.WriteLine("</head>");
                    writer.WriteLine("<body class=\"bg-" + (darkmode ? "dark" : "light") + "\">");
                    writer.WriteLine("</br>");
                    writer.WriteLine("");
                    writer.WriteLine($"<table style=\"width:100%\" class=\"table table-striped {lightOrDarkTable}\">");
                    writer.WriteLine("<tr>");
                    writer.WriteLine("<thead class=\"thead-" + (darkmode ? "light" : "dark") + "\">");
                    writer.WriteLine($"<th>Name</th><th>Version</th><th>License Expressions</th><th>Source of License</th><th>Source of Code</th>");
                    writer.WriteLine("</thead>");
                    writer.WriteLine("</tr>");
                }
                for (int i = 0; i < sbom.Length; i++)
                {
                    writer.WriteLine("<tr>");
                    writer.WriteLine("<td>" + sbom[i].Name + "</td>");
                    writer.WriteLine("<td>" + sbom[i].Version + "</td>");
                    if (sbom[i].License.Length != 1)
                    {
                        writer.WriteLine($"<td> <details> <summary>{sbom[i].LicenseType}</summary> <pre style=\"color:{color};\">");
                        foreach (string line in sbom[i].License)
                        {
                            writer.WriteLine(line);
                        }
                        writer.WriteLine("</pre></details> </td>");
                    }
                    else
                    {
                        writer.Write($"<td>{sbom[i].LicenseType}</td>");
                    }

                    writer.WriteLine(String.IsNullOrEmpty(sbom[i].SourceOfLicense) ? "<td></td>" : $"<td><a href=\"{sbom[i].SourceOfLicense}\">license</a> </td>");
                    writer.WriteLine(String.IsNullOrEmpty(sbom[i].SourceOfCode) ? "<td></td>" : $"<td><a href=\"{sbom[i].SourceOfCode}\">code</a> </td>");

                    writer.WriteLine("</tr>");
                }
            }
        }

        static void DeleteFile(string directory, bool delete)
        {
            if (delete)
            {
                if (File.Exists(directory))
                    File.Delete(directory);
            }
        }
    }
}