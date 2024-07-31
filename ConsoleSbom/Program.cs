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
        public static List<string[]> Libraries = new List<string[]>();

        static void Main(string[] args)
        {
            // GRGR: Args variable is not used
            Args Args = new Args(args);

            if (args[0] == "/h")
            {
                return;
            }

            bool addToFile = Args.Add;

            Sbom[] sbom;

            string[] directories = FindLicensesFolders(Args.PathLibraries);

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
                        // GRGR: why not if (Args.FileType == "csv" || Args.FileType == "all") ?
                        if (Args.FileType == "csv")
                            ConvertToCsv(Args.FileName, sbom, Args.PathOutput, 1, Args.Seperator, true);
                        if (Args.FileType == "html")
                            ConvertToHtml(Args.FileName, sbom, Args.PathOutput, Args.DarkMode, false);      // GRGR: newFile is false ... why?
                        if (Args.FileType == "spdx")
                            ConvertToSpdx(Args.FileName, sbom, Args.PathOutput, Args.PathSpdxHeader, true);
                        if (Args.FileType == "all" && !addToFile)
                        {
                            ConvertToCsv(Args.FileName, sbom, Args.PathOutput, 1, Args.Seperator, true);
                            ConvertToHtml(Args.FileName, sbom, Args.PathOutput, Args.DarkMode, true);
                            ConvertToSpdx(Args.FileName, sbom, Args.PathOutput, Args.PathSpdxHeader, true);
                        }
                    }

                    // GRGR: add comment
                    addToFile = directories.Length > 1;
                }
            }
            Console.WriteLine("Done");
        }

        static Sbom CreateSbom(string directory)
        {
            Sbom output = new Sbom();

            output.Version = ReadFile(Path.Combine(directory, "VERSION"));
            // GRGR: call UrlCreator only once
            output.SourceOfLicense = UrlCreator(Path.Combine(directory, "lic-src.url"))[0];
            output.LicenseType = ReadFile(Path.Combine(directory, "LICENSETYPE"));
            // GRGR: use Path.GetFileName instead of splitting
            string[] name = directory.Split(new char[] { '/', '\\' });
            output.Name = name[name.Length - 1];
            output.SourceOfCode = UrlCreator(Path.Combine(directory, "lic-src.url"))[1];
            output.Purl = ReadFile(Path.Combine(directory, "PURL"));
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
            string[] licensesFolders = Array.Empty<string>();

            if (Directory.Exists(directory))
            {
                licensesFolders = Directory.GetDirectories(directory, "Licenses", SearchOption.AllDirectories);
            }

            return licensesFolders;
        }

        public static string[] FindFoldersWithLicenses(string directory)
        {
            string[] licensesFolders = Array.Empty<string>();

            if (Directory.Exists(directory))
            {
                licensesFolders = Directory.GetFiles(directory, "LICENSE", SearchOption.AllDirectories);
            }

            return licensesFolders;
        }

        // GRGR: naming (ReadFirstLine maybe)
        public static string ReadFile(string directory)
        {
            if (File.Exists(directory))
            {
                return File.ReadAllLines(directory)[0];
            }
            return String.Empty;
        }

        // GRGR: naming (ReadAllLines maybe)
        public static string[] LicenseCreator(string directory)
        {
            if (File.Exists(directory))
            {
                return File.ReadAllLines(directory);
            }
            return new string[1];
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

            using (StreamWriter writer = new StreamWriter(filename, false))
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
                    writer.WriteLine($"<table style=\"width:100%\" class=\"table table-striped" + (darkmode ? "table-dark" : "") + "\">");
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