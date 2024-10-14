using System;
using System.IO;
using System.Net;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
namespace ConsoleSBOM
{
    public class Program
    {
        const string BOOTSTRAP = "<link rel=\"stylesheet\" href=\"https://cdn.jsdelivr.net/npm/bootstrap@4.4.1/dist/css/bootstrap.min.css\" integrity=\"sha384-Vkoo8x4CGsO3+Hhxv8T/Q5PaXtkKtu6ug5TOeNV6gBiFeWPGFN9MuhOf23Q9Ifjh\" crossorigin=\"anonymous\">";
        const string JQUERY = "<script src=\"https://code.jquery.com/jquery-3.4.1.slim.min.js\" integrity=\"sha384-J6qa4849blE2+poT4WnyKhv5vZF5SrPo0iEjwBvKU7imGFAV0wwj1yYfoRSJoZ+n\" crossorigin=\"anonymous\" defer></script>";
        const string JSDELIVRPOPPER = "<script src=\"https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.min.js\" integrity=\"sha384-Q6E9RHvbIyZFJoft+2mJbHaEWldlvI9IOYy5n3zV9zzTtmI3UksdQRVvoxMfooAo\" crossorigin=\"anonymous\" defer></script>";
        const string JSDELIVRBOOTSTRAP = "<script src=\"https://cdn.jsdelivr.net/npm/bootstrap@4.4.1/dist/js/bootstrap.min.js\" integrity=\"sha384-wfSDF2E50Y2D1uUdj0O3uMBJnjuUD4Ih7YwaYd1iqfktj0Uod8GCExl3Og8ifwB6\" crossorigin=\"anonymous\" defer></script>";
        public static List<string[]> Libraries = new List<string[]>();

        static void Main(string[] args)
        {
            new Args(args);

            if (args[0] == "/h")
            {
                return;
            }

            bool addToFile = Args.Add;

            Sbom[] sbom;

            string[] directories = FindLicenses(Args.PathLibraries);

            foreach (string directory in directories)
            {
                sbom = CreateSbomList(directory, Args.Log, Args.LogFile, Args.PathOutput, addToFile).ToArray();

                if (sbom.Length != 0)
                {
                    if (addToFile)
                    {
                        if (Args.FileType == "csv" || Args.FileType == "all")
                        {
                            string path = Path.Combine(Args.PathOutput, Args.FileName + ".csv");
                            if (File.Exists(path))
                            {
                                string[] csv = File.ReadAllLines(Path.Combine(Args.PathOutput, Args.FileName + ".csv"));
                                ConvertToCsv(Args.FileName, sbom, Args.PathOutput, csv.Length, Args.Seperator, false);
                            }
                        }

                        if (Args.FileType == "html" || Args.FileType == "all")
                        {
                            string path = Path.Combine(Args.PathOutput, Args.FileName + ".html");
                            if (File.Exists(path))
                            {
                                ConvertToHtml(Args.FileName, sbom, Args.PathOutput, Args.DarkMode, false);
                            }
                        }

                        if (Args.FileType == "spdx" || Args.FileType == "all")
                        {
                            string path = Path.Combine(Args.PathOutput, Args.FileName + ".json");
                            if (File.Exists(path))
                            {
                                ConvertToSpdx(Args.FileName, sbom, Args.PathOutput, Args.PathSpdxHeader, false);
                            }
                        }
                    }
                    else
                    {
                        if (Args.FileType == "csv" || Args.FileType == "all")
                            ConvertToCsv(Args.FileName, sbom, Args.PathOutput, 1, Args.Seperator, true);
                        if (Args.FileType == "html" || Args.FileType == "all")
                            ConvertToHtml(Args.FileName, sbom, Args.PathOutput, Args.DarkMode, true);
                        if (Args.FileType == "spdx" || Args.FileType == "all")
                            ConvertToSpdx(Args.FileName, sbom, Args.PathOutput, Args.PathSpdxHeader, true);
                    }

                    // We don't want to create a new file and overwrite the file we created on the previous run
                    addToFile = directories.Length > 1;
                }
            }
            Console.WriteLine("Done");
        }

        /// <summary>
        /// Gets given a directory and saves the data from this directory to a Sbom
        /// </summary>
        static Sbom CreateSbom(string directory)
        {
            Sbom output = new Sbom();
            string[] urls = UrlCreator(Path.Combine(directory, "lic-src.url"));

            output.Version = ReadFirstLine(Path.Combine(directory, "VERSION"));
            output.SourceOfLicense = urls[0];
            output.LicenseType = ReadFirstLine(Path.Combine(directory, "LICENSETYPE"));
            output.Name = Path.GetFileName(directory);
            output.SourceOfCode = urls[1];
            output.Purl = ReadFirstLine(Path.Combine(directory, "PURL"));
            output.License = ReadAllLines(Path.Combine(directory, "LICENSE"));
            output.Path = Path.GetRelativePath(Args.PathOutput, Path.GetDirectoryName(directory) ?? string.Empty);

            return output;
        }

        /// <summary>
        /// Creates a Sbom List and a log, either in a file or as Exceptions
        /// </summary>
        public static List<Sbom> CreateSbomList(string parentDirectory, bool createLog, bool logFile, string outputLoc, bool multipleLicenses)
        {
            string[] directories = FindFoldersWithLicenses(parentDirectory);

            List<Sbom> result = new List<Sbom>();

            foreach(string directory in directories) 
            {
                Sbom sbomToAdd = CreateSbom(Path.GetDirectoryName(directory)!);

                if (!CheckRepeatingLibrary(sbomToAdd))
                    result.Add(sbomToAdd);
            }

            if (createLog)
                CreateLog(result.ToArray(), logFile, outputLoc, multipleLicenses);

            return result;
        }

        /// <summary>
        /// Adds Sbom name and Version to a List and returns if the Sbom was already inside
        /// </summary>
        public static bool CheckRepeatingLibrary(Sbom sbomToAdd)
        {
            string[] tmp = { sbomToAdd.Name, sbomToAdd.Version + "" };

            foreach (string[] library in Libraries)
            {
                if (library[0] == tmp[0] && library[1] == tmp[1])
                {
                    return true;
                }
            }

            Libraries.Add(tmp);
            return false;
        }

        /// <summary>
        /// Gets given a directory and returns at index 0 the source of code and at index 1 the source of license
        /// </summary>
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

        /// <summary>
        /// Searches for folders called "Licenses"
        /// </summary>
        public static string[] FindLicenses(string directory)
        {
            string[] licensesFolders = Array.Empty<string>();

            if (Directory.Exists(directory))
            {
                licensesFolders = Directory.GetDirectories(directory, "Licenses", SearchOption.AllDirectories);
            }

            return licensesFolders;
        }

        /// <summary>
        /// Returns directories containing files called "LICENSETYPE"
        /// </summary>
        public static string[] FindFoldersWithLicenses(string directory)
        {
            string[] licensesFolders = Array.Empty<string>();

            if (Directory.Exists(directory))
            {
                licensesFolders = Directory.GetFiles(directory, "LICENSETYPE", SearchOption.AllDirectories);
                Array.Sort(licensesFolders, new ExplorerLikePathComparer());
            }

            return licensesFolders;
        }

        // not perfect, but orders the directories in a similar way as the windows explorer does
        public class ExplorerLikePathComparer : IComparer<string>
        {

            [DllImport("shlwapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
            static extern int StrCmpLogicalW(string x, string y);

            public int Compare(string x, string y)
            {
                return StrCmpLogicalW(x, y);
            }

        }

        /// <summary>
        /// Reads first line of a file, if the file exists
        /// </summary>
        public static string ReadFirstLine(string directory)
        {
            if (File.Exists(directory))
            {
                return File.ReadAllLines(directory)[0];
            }
            return String.Empty;
        }

        /// <summary>
        /// Reads all lines of a file, if the file exists
        /// </summary>
        public static string[] ReadAllLines(string directory)
        {
            if (File.Exists(directory))
            {
                return File.ReadAllLines(directory);
            }
            return Array.Empty<string>();
        }

        /// <summary>
        /// Creates a log file or throws an exception, if any value of any Sbom is empty
        /// </summary>
        static void CreateLog(Sbom[] sbom, bool logFile, string fileName, bool multipleLicenses)
        {
            DeleteFile(Path.Combine(fileName, "log.txt"), logFile && !multipleLicenses);

            for (int i = 0; i < sbom.Length; i++)
            {
                var name = sbom[i].Name;
                var path = sbom[i].Path;

                if (!logFile)
                {
                    if (String.IsNullOrEmpty(sbom[i].Version))
                        throw new Exception($"There is no Version in {name} ({path})");
                    // deactivated, because we can not guarantee that the SourceOfCode, generated from the .url file, is a valid URL in every case
                    //if (String.IsNullOrEmpty(sbom[i].SourceOfCode))
                    //    throw new Exception($"There is no Url in {name} ({path})");
                    if (String.IsNullOrEmpty(sbom[i].LicenseType))
                        throw new Exception($"There is no Licensetype in {name} ({path})");
                    if (sbom[i].License.Length == 0)
                        throw new Exception($"There is no Licensetext in {name} ({path})");
                    if (String.IsNullOrEmpty(sbom[i].Purl))
                        throw new Exception($"There is no Purl in {name} ({path})");
                }
                else
                {
                    using (StreamWriter sw = new StreamWriter(Path.Combine(fileName, "log.txt"), true))
                    {
                        if (String.IsNullOrEmpty(sbom[i].Version))
                            sw.WriteLine($"There is no Version in {name} ({path})");
                        // deactivated, because we can not guarantee that the SourceOfCode, generated from the .url file, is a valid URL in every case
                        //if (String.IsNullOrEmpty(sbom[i].SourceOfCode))
                        //    sw.WriteLine($"There is no Url in {name} ({path})");
                        if (String.IsNullOrEmpty(sbom[i].LicenseType))
                            sw.WriteLine($"There is no Licensetype in {name} ({path})");
                        if (sbom[i].License.Length == 0)
                            sw.WriteLine($"There is no Licensetext in {name} ({path})");
                        if (String.IsNullOrEmpty(sbom[i].Purl))
                            sw.WriteLine($"There is no Purl in {name} ({path})");
                    }
                }
            }
        }

        /// <summary>
        /// Creates a .json file ind the spdx format
        /// </summary>
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

            using (StreamWriter writer = new StreamWriter(filename, false))
            {

                foreach (string line in header)
                {
                    writer.WriteLine(line);
                }

                for (int i = 0; i < sbom.Length; i++)
                {
                    var licenseTypeKey = sbom[i].LicenseType.Equals("Commercial", StringComparison.OrdinalIgnoreCase)
                        ? "name"
                        : "id";
                    var purlKey = sbom[i].Purl.StartsWith("cpe", StringComparison.OrdinalIgnoreCase)
                        ? "cpe"
                        : "purl";

                    writer.WriteLine(newFile ? "" : "   ,");
                    writer.WriteLine("    {");
                    writer.WriteLine("      \"type\": \"library\",");
                    writer.WriteLine($"      \"name\": \"{sbom[i].Name}\",");
                    writer.WriteLine($"      \"version\": \"{sbom[i].Version}\",");
                    writer.WriteLine("      \"licenses\": [");
                    writer.WriteLine("        {");
                    writer.WriteLine("          \"license\": {");
                    writer.WriteLine($"            \"{licenseTypeKey}\": \"{sbom[i].LicenseType}\",");
                    writer.WriteLine($"            \"url\": \"{sbom[i].SourceOfLicense}\"");
                    writer.WriteLine("          }");
                    writer.WriteLine("        }");
                    writer.WriteLine("      ],");
                    writer.WriteLine($"      \"{purlKey}\": \"{sbom[i].Purl}\"");
                    writer.WriteLine("    }");
                    newFile = false;
                }

                writer.WriteLine("  ]");
                writer.WriteLine("}");

            }
        }

        /// <summary>
        /// Converts the sbom[] to a csv
        /// </summary>
        static void ConvertToCsv(string filename, Sbom[] sbom, string directory, int length, string seperator, bool newFile)
        {
            filename = Path.Combine(directory, filename + ".csv");

            using (StreamWriter writer = new StreamWriter(filename, !newFile))
            {
                if (newFile)
                {
                    // deactivated, because we can not guarantee that the SourceOfCode, generated from the .url file, is a valid URL in every case
                    //writer.WriteLine($"0{seperator}Name{seperator}LicenseExpressions{seperator}Source of License{seperator}Version{seperator}Source of Code{seperator}Purl{seperator}");
                    writer.WriteLine($"0{seperator}Name{seperator}LicenseExpressions{seperator}Source of License{seperator}Version{seperator}Purl{seperator}Component{seperator}");
                }

                for (int i = 0; i < sbom.Length; i++)
                {
                    writer.Write((i + length) + seperator);
                    writer.Write(sbom[i].Name + seperator);
                    writer.Write(sbom[i].LicenseType + seperator);
                    writer.Write(sbom[i].SourceOfLicense + seperator);
                    writer.Write(sbom[i].Version + seperator);
                    // deactivated, because we can not guarantee that the SourceOfCode, generated from the .url file, is a valid URL in every case
                    //writer.Write(sbom[i].SourceOfCode + seperator);   
                    writer.Write(sbom[i].Purl + seperator);
                    writer.Write(sbom[i].Path + seperator);
                    writer.WriteLine();
                }

            }
        }

        /// <summary>
        /// Converts the sbom[] to a html table
        /// </summary>
        static void ConvertToHtml(string filename, Sbom[] sbom, string directory, bool darkmode, bool newFile)
        {
            filename = Path.Combine(directory, filename + ".html");
            using (StreamWriter writer = new StreamWriter(filename, !newFile))
            {
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
                    writer.WriteLine($"<table style=\"width:100%\" class=\"table table-striped" + (darkmode ? " table-dark" : "") + "\">");
                    writer.WriteLine("<tr>");
                    writer.WriteLine("<thead class=\"thead-" + (darkmode ? "light" : "dark") + "\">");
                    // deactivated, because we can not guarantee that the SourceOfCode, generated from the .url file, is a valid URL in every case
                    //writer.WriteLine($"<th>Name</th><th>Version</th><th>License Expressions</th><th>Source of License</th><th>Source of Code</th>");
                    writer.WriteLine($"<th>Name</th><th>Version</th><th>License Expressions</th><th>Source of License</th>");
                    writer.WriteLine("</thead>");
                    writer.WriteLine("</tr>");
                }
                for (int i = 0; i < sbom.Length; i++)
                {
                    writer.WriteLine($"<tr style=\"color:{color}\">");
                    writer.WriteLine("<td>" + sbom[i].Name + "</td>");
                    writer.WriteLine("<td>" + sbom[i].Version + "</td>");
                    if (sbom[i].License.Length != 0)     // do not add details if the license is empty or doesn't exist
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
                    // deactivated, because we can not guarantee that the SourceOfCode, generated from the .url file, is a valid URL in every case
                    //writer.WriteLine(String.IsNullOrEmpty(sbom[i].SourceOfCode) ? "<td></td>" : $"<td><a href=\"{sbom[i].SourceOfCode}\">code</a> </td>");

                    writer.WriteLine("</tr>");
                }
            }
        }

        /// <summary>
        /// Deletes the given file, if it exists and delete is true
        /// </summary>
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