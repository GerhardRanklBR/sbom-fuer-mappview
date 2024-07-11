using System;
using System.IO;
using System.Net;
using System.Text;
using System.Collections.Generic;
namespace ConsoleSBOM
{
    public class Program
    {
        const string BOOTSTRAP = "<link rel=\"stylesheet\" href=\"https://cdn.jsdelivr.net/npm/bootstrap@4.4.1/dist/css/bootstrap.min.css\" integrity=\"sha384-Vkoo8x4CGsO3+Hhxv8T/Q5PaXtkKtu6ug5TOeNV6gBiFeWPGFN9MuhOf23Q9Ifjh\" crossorigin=\"anonymous\">";
        const string JQUERY = "<script src=\"https://code.jquery.com/jquery-3.4.1.slim.min.js\" integrity=\"sha384-J6qa4849blE2+poT4WnyKhv5vZF5SrPo0iEjwBvKU7imGFAV0wwj1yYfoRSJoZ+n\" crossorigin=\"anonymous\" defer></script>";
        const string JSDELIVRPOPPER = "<script src=\"https://cdn.jsdelivr.net/npm/popper.js@1.16.0/dist/umd/popper.min.js\" integrity=\"sha384-Q6E9RHvbIyZFJoft+2mJbHaEWldlvI9IOYy5n3zV9zzTtmI3UksdQRVvoxMfooAo\" crossorigin=\"anonymous\" defer></script>";
        const string JSDELIVRBOOTSTRAP = "<script src=\"https://cdn.jsdelivr.net/npm/bootstrap@4.4.1/dist/js/bootstrap.min.js\" integrity=\"sha384-wfSDF2E50Y2D1uUdj0O3uMBJnjuUD4Ih7YwaYd1iqfktj0Uod8GCExl3Og8ifwB6\" crossorigin=\"anonymous\" defer></script>";


        static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                if (args[0] != "/h")
                {
                    if (Directory.Exists(args[0]) && Directory.Exists(args[3]))
                    {
                        if (args.Length >= 4)
                        {
                            string pathLibraries = args[0];
                            string filetype = args[1];
                            string filename = args[2];
                            string pathOutput = args[3];

                            bool[] optArgsBool = OptionalParameter(args);

                            string seperator = ";";
                            if (optArgsBool[3])
                                seperator = ",";

                            string lightOrDarkTable = "";

                            if (optArgsBool[4])
                                lightOrDarkTable = "table-dark";

                            Sbom[] sbom;

                            string[] directories = FindLicensesFolders(pathLibraries);

                            bool multipleLicenses = false;

                            foreach (string directory in directories)
                            {
                                sbom = CreateSbomList(directory, optArgsBool[0], optArgsBool[1], pathOutput, multipleLicenses).ToArray();

                                bool tmp = false;

                                tmp = filetype == "all" || filetype == "spdx";

                                if (optArgsBool[2] || multipleLicenses)
                                {
                                    if (filetype == "csv" || filetype == "all")
                                    {
                                        string[] csv;
                                        string path = Path.Combine(pathOutput, filename + ".csv");
                                        if (File.Exists(path))
                                        {
                                            csv = File.ReadAllLines(Path.Combine(pathOutput, filename + ".csv"));
                                            ConvertToCsv(filename, sbom, pathOutput, csv.Length, seperator);
                                        }
                                        else
                                            tmp = true;

                                    }

                                    if (filetype == "html" || filetype == "all")
                                    {
                                        string path = Path.Combine(pathOutput, filename + ".html");
                                        if (File.Exists(path))
                                        {
                                            ConvertToHtml(filename, sbom, pathOutput, lightOrDarkTable);
                                        }
                                        else
                                            tmp = true;
                                    }
                                }
                                else
                                {
                                    if (filetype == "csv")
                                        ConvertToCsvAndCreate(filename, sbom, pathOutput, seperator);
                                    if (filetype == "html")
                                        ConvertToHtmlAndCreate(filename, sbom, pathOutput, lightOrDarkTable);
                                    if (filetype == "all")
                                    {
                                        if (!multipleLicenses)
                                        {
                                            ConvertToCsvAndCreate(filename, sbom, pathOutput, seperator);
                                            ConvertToHtmlAndCreate(filename, sbom, pathOutput, lightOrDarkTable);
                                        }
                                    }
                                }

                                if(filetype == "spdx" || filetype == "all"){
                                    ConvertFromSbomToSpdx(filename, sbom, pathOutput);
                                }

                                multipleLicenses = directories.Length > 1;
                            }

                            Console.WriteLine("Done");
                        }
                        else
                        {
                            Console.WriteLine("Not all args were provided");
                        }
                    }
                    else
                    {
                        Console.WriteLine("The directory doesn't exist");
                    }
                }
                else // /h
                {
                    Console.WriteLine("----------------------------------------------------------------------------------------------");
                    Console.WriteLine("The first arg should be the complete filepath to the libaries");
                    Console.WriteLine("The second should be the filetype of the file (\"csv\", \"xmll\", \"html\", \"all\")");
                    Console.WriteLine("The third value should be the output filename");
                    Console.WriteLine("The fourth arg should be the full filepath to the directory, where the new file should end up");
                    Console.WriteLine("[The fifth arg should be \"log\" if a log should be provided]");
                    Console.WriteLine("[The sixth arg should be \"file\" if the log should be provided in a file]");
                    Console.WriteLine("[The seventh arg should be \"add\" if the new csv should be added at the end of the old one]");
                    Console.WriteLine("[The eighth arg should be a \",\" if the csv should use , as seperators");
                    Console.WriteLine("[The ninth arg should be \"dark\" if the html table shoul be in darkmode]");
                    Console.WriteLine("Note: The args in [] are interchangeable with another, the order doesn't matter");
                    Console.WriteLine("----------------------------------------------------------------------------------------------");

                }
            }
            else
            {
                Console.WriteLine("Not enough parameter");
            }
        }
        static bool[] OptionalParameter(string[] input)
        {
            bool[] output = new bool[5];

            for (int i = 4; i < input.Length; i++)
            {
                if (input[i] == "log")
                    output[0] = true;

                if (input[i] == "file")
                    output[1] = true;

                if (input[i] == "add")
                    output[2] = true;

                if (input[i] == ",")
                    output[3] = true;

                if (input[i] == "dark")
                    output[4] = true;
            }

            if (!output[0])
                output[1] = false;

            return output;
        }

        static Sbom CreateSbom(string directory)
        {
            Sbom output = new Sbom();

            output.Version = VersionCreator(Path.Combine(directory, "VERSION"));
            output.SourceOfLicense = UrlCreator(Path.Combine(directory, "lic-src.url"))[0];
            output.LicenseType = LicenseTypeCreator(Path.Combine(directory, "LICENSETYPE"));
            string[] name = directory.Split(new char[] { '/', '\\' });
            output.Directory = name[name.Length - 1];
            output.SourceOfCode = UrlCreator(Path.Combine(directory, "lic-src.url"))[1];
            output.Purl = PurlCreator(Path.Combine(directory, "PURL"));
            output.License = LicenseCreator(Path.Combine(directory, "LICENSE"));

            return output;
        }

        public static List<Sbom> CreateSbomList(string parentDirectory, bool createLog, bool logFile, string outputLoc, bool multipleLicenses)
        {
            string[] directories = Directory.GetDirectories(parentDirectory);

            List<Sbom> result = new List<Sbom>();

            for (int i = 0; i < directories.Length; i++)
            {
                result.Add(CreateSbom(directories[i]));
            }

            if (createLog)
                CreateLog(result.ToArray(), logFile, outputLoc, multipleLicenses);

            return result;
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

        static void ConvertToCsvAndCreate(string filename, Sbom[] sbom, string directory, string seperator)
        {
            if (File.Exists(Path.Combine(directory, filename + ".csv")))
                File.Delete(Path.Combine(directory, filename + ".csv"));

            using (StreamWriter writer = new StreamWriter(Path.Combine(directory, filename + ".csv"), true))
            {
                writer.WriteLine($"0{seperator}Name{seperator}LicenseExpressions{seperator}Source of License{seperator}Version{seperator}Source of Code{seperator}Purl{seperator}");

                for (int i = 0; i < sbom.Length; i++)
                {
                    writer.Write((i + 1) + seperator);
                    writer.Write(sbom[i].Directory + seperator);
                    writer.Write(sbom[i].LicenseType + seperator);
                    writer.Write(sbom[i].SourceOfLicense + seperator);
                    writer.Write(sbom[i].Version + seperator);
                    writer.Write(sbom[i].SourceOfCode + seperator);
                    writer.Write(sbom[i].Purl + seperator);
                    writer.WriteLine();
                }

            }
        }

        static void CreateLog(Sbom[] sbom, bool logFile, string fileName, bool multipleLicenses)
        {
            if (File.Exists(Path.Combine(fileName, "log.txt")) && logFile && !multipleLicenses)
                File.Delete(Path.Combine(fileName, "log.txt"));

            for (int i = 0; i < sbom.Length; i++)
            {
                string name = sbom[i].Directory;

                if (!logFile)
                {
                    if (String.IsNullOrEmpty(sbom[i].Version))
                        Console.WriteLine($"There is no Version in {name}");
                    if (String.IsNullOrEmpty(sbom[i].SourceOfCode))
                        Console.WriteLine($"There is no Url in {name}");
                    if (String.IsNullOrEmpty(sbom[i].LicenseType))
                        Console.WriteLine($"There is no Licensetype in {name}");
                    if (sbom[i].License.Length != 1)
                        Console.WriteLine($"There is no Licensetext in {name}");
                    if (String.IsNullOrEmpty(sbom[i].Purl))
                        Console.WriteLine($"There is no Purl in {name}");
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
                        if (sbom[i].License.Length != 1)
                            sw.WriteLine($"There is no Licensetext in {name}");
                        if (String.IsNullOrEmpty(sbom[i].Purl))
                            sw.WriteLine($"There is no Purl in {name}");
                    }
                }
            }
        }

        static void ConvertFromSbomToSpdx(string filename, Sbom[] sbom, string directory)
        {
            for (int i = 0; i < sbom.Length; i++)
            {
                if (!Directory.Exists(Path.Combine(directory, filename)))
                    Directory.CreateDirectory(Path.Combine(directory, filename));


                string spdxName = Path.Combine(directory, filename, sbom[i].Directory + ".spdx");
                ToSpdxFile(spdxName, sbom[i]);
            }
        }

        static void ToSpdxFile(string fileName, Sbom sbom)
        {
            using (StreamWriter sw = new StreamWriter(fileName))
            {
                sw.WriteLine("SPDXVersion: SPDX-2.2");
                sw.WriteLine("DataLicense: CC0-1.0");
                sw.WriteLine($"PackageName: {sbom.Directory}");
                sw.WriteLine($"PackageVersion: {sbom.Version}");
                sw.WriteLine($"PackageDownloadLocation: {sbom.SourceOfCode}");
                sw.WriteLine($"PackageLicenseDeclared: {sbom.LicenseType}");
                sw.WriteLine($"PackageLicenseConcluded: {sbom.LicenseType}");
                sw.WriteLine($"PackageLicenseInfoFromFiles: {sbom.SourceOfLicense}");
                sw.WriteLine($"PackageHomePage: {sbom.Purl}");
            }
        }

        static void ConvertToCsv(string filename, Sbom[] sbom, string directory, int length, string seperator)
        {
            using (StreamWriter writer = new StreamWriter(Path.Combine(directory, filename + ".csv"), true))
            {

                for (int i = 0; i < sbom.Length; i++)
                {
                    writer.Write((i + length) + seperator);
                    writer.Write(sbom[i].Directory + seperator);
                    writer.Write(sbom[i].LicenseType + seperator);
                    writer.Write(sbom[i].SourceOfLicense + seperator);
                    writer.Write(sbom[i].Version + seperator);
                    writer.Write(sbom[i].SourceOfCode + seperator);
                    writer.Write(sbom[i].Purl + seperator);
                    writer.WriteLine();
                }

            }
        }

        static void ConvertToHtml(string filename, Sbom[] sbom, string directory, string lightOrDarkTable)
        {
            using (StreamWriter writer = new StreamWriter(Path.Combine(directory, filename + ".html"), true))
            {
                string color = "black";
                if(lightOrDarkTable == "table-dark")
                    color = "white";

                for (int i = 0; i < sbom.Length; i++)
                {
                    writer.WriteLine("<tr>");
                    writer.Write("<td>" + sbom[i].Directory + "</td>");
                    writer.Write("<td>" + sbom[i].Version + "</td>");
                    if(sbom[i].License.Length != 1)
                    {
                        writer.Write($"<td> <details> <summary>{sbom[i].LicenseType}</summary> <pre style=\"color:{color};\">");
                        foreach(string line in sbom[i].License)
                        {
                            writer.WriteLine(line);
                        }
                        writer.Write("</pre></details> </td>");
                    }
                    else
                    {
                        writer.Write($"<td>{sbom[i].LicenseType}</td>");
                    }
                    if (!String.IsNullOrEmpty(sbom[i].SourceOfLicense))
                    {
                        writer.Write($"<td><a href=\"{sbom[i].SourceOfLicense}\">link</a> </td>");
                    }
                    else
                    {
                        writer.Write($"<td></td>");
                    }
                    if (!String.IsNullOrEmpty(sbom[i].SourceOfCode))
                    {
                        writer.Write($"<td><a href=\"{sbom[i].SourceOfCode}\">link</a> </td>");
                    }
                    else
                    {
                        writer.Write($"<td></td>");
                    }
                    writer.WriteLine("</tr>");
                }
            }
        }

        static void ConvertToHtmlAndCreate(string filename, Sbom[] sbom, string directory, string lightOrDarkTable)
        {
            if (File.Exists(Path.Combine(directory, filename + ".html")))
                File.Delete(Path.Combine(directory, filename + ".html"));

            using (StreamWriter writer = new StreamWriter(Path.Combine(directory, filename + ".html"), true))
            {
                // Print HTML Header
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
                    writer.WriteLine("<body>");
                    writer.WriteLine("</br>");
                    writer.WriteLine("");
                    writer.WriteLine($"<table style=\"width:100%\" class=\"table table-striped {lightOrDarkTable}\">");
                    writer.WriteLine("<tr>");
                    writer.WriteLine($"<th>Name</th><th>Version</th><th>LicenseExpressions</th><th>Source of License</th><th>Source of Code</th>");
                    writer.WriteLine("<tr>");
                }

                string color = "black";
                if(lightOrDarkTable == "table-dark")
                    color = "white";

                for (int i = 0; i < sbom.Length; i++)
                {
                    writer.WriteLine("<tr>");
                    writer.Write("<td>" + sbom[i].Directory + "</td>");
                    writer.Write("<td>" + sbom[i].Version + "</td>");
                    if(sbom[i].License.Length != 1)
                    {
                        writer.Write($"<td> <details> <summary>{sbom[i].LicenseType}</summary> <pre style=\"color:{color};\">");
                        foreach(string line in sbom[i].License)
                        {
                            writer.WriteLine(line);
                        }
                        writer.Write("</pre></details> </td>");
                    }
                    else
                    {
                        writer.Write($"<td>{sbom[i].LicenseType}</td>");
                    }
                    if (!String.IsNullOrEmpty(sbom[i].SourceOfLicense))
                    {
                        writer.Write($"<td><a href=\"{sbom[i].SourceOfLicense}\">link</a> </td>");
                    }
                    else
                    {
                        writer.Write($"<td></td>");
                    }
                    if (!String.IsNullOrEmpty(sbom[i].SourceOfCode))
                    {
                        writer.Write($"<td><a href=\"{sbom[i].SourceOfCode}\">link</a> </td>");
                    }
                    else
                    {
                        writer.Write($"<td></td>");
                    }
                    writer.WriteLine("</tr>");
                }
            }
        }
    }
}