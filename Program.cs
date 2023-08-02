using System;
using System.IO;
using System.Net;
using System.Text;

namespace ConsoleSBOM
{
    public class Program
    {
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

                            bool[] optArgs = OptionalParameter(args);

                            string germanOrEnglish = ";";

                            if (optArgs[3])
                                germanOrEnglish = ",";

                            Sbom[] sbom;

                            string[] directories = FindLicensesFolders(args[0]);

                            bool multipleLicenses = false;

                            foreach (string directory in directories)
                            {
                                sbom = CreateSbomArray(directory, optArgs[0], optArgs[1], args[3], multipleLicenses).ToArray();

                                bool tmp = false;

                                if (optArgs[2] || multipleLicenses)
                                {
                                    string[] csv;

                                    if (File.Exists(Path.Combine(args[3], args[2] + ".csv")))
                                    {
                                        csv = File.ReadAllLines(Path.Combine(args[3], args[2] + ".csv"));
                                        ConvertToCsv(args[2], sbom, args[3], csv, germanOrEnglish);
                                    }
                                    else
                                        tmp = true;
                                }
                                else
                                    tmp = true;

                                tmp = args[1] == "all" || args[1] == "spdx";


                                if (tmp)
                                {
                                    if (args[1] == "csv")
                                        ConvertToCsvAndCreate(args[2], sbom, args[3], germanOrEnglish);
                                    if (args[1] == "spdx")
                                        ConvertFromSbomToSpdx(args[2], sbom, args[3]);
                                    if (args[1] == "all")
                                    {
                                        if (!multipleLicenses)
                                            ConvertToCsvAndCreate(args[2], sbom, args[3], germanOrEnglish);
                                        ConvertFromSbomToSpdx(args[2], sbom, args[3]);
                                    }
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
                else
                {
                    Console.WriteLine("The first arg should be the complete filepath to the libaries");
                    Console.WriteLine();
                    Console.WriteLine("The second should be the filetype of the file (csv, xmll, all)");
                    Console.WriteLine();
                    Console.WriteLine("The third value should be the output filename");
                    Console.WriteLine();
                    Console.WriteLine("The fourth arg should be the full filepath to the directory, where the new file should end up");
                    Console.WriteLine();
                    Console.WriteLine("[The fifth arg should be log if a log should be provided]");
                    Console.WriteLine();
                    Console.WriteLine("[The sixth arg should be file if the log should be provided in a file]");
                    Console.WriteLine();
                    Console.WriteLine("[The seventh arg should be add if the new csv should be added at the end of the old one]");
                    Console.WriteLine();
                    Console.WriteLine("[The eighth arg should be a \",\" if the csv should use , as seperators");
                    Console.WriteLine();
                    Console.WriteLine("Note: The args in [] are interchangeable with another, the order doesn't mather");
                }
            }
            else
            {
                Console.WriteLine("Not enough parameter");
            }

        }

        static bool[] OptionalParameter(string[] input)
        {
            bool[] output = new bool[4];

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
            }

            if (!output[0])
                output[1] = false;

            return output;
        }

        static Sbom CreateSbom(string[] values)
        {
            Sbom output = new Sbom();

            output.Version = values[0];
            output.SourceOfLicense = values[1];
            output.License = values[2];
            output.Directory = values[3];
            output.SourceOfCode = values[4];
            output.Purl = values[5];

            return output;
        }

        public static List<Sbom> CreateSbomArray(string parentDirectory, bool createLog, bool logFile, string outputLoc, bool multipleLicenses)
        {
            string[] directories = Directory.GetDirectories(parentDirectory);

            List<Sbom> result = new List<Sbom>();

            for (int i = 0; i < directories.Length; i++)
            {
                string[] values = ReadSbomValue(directories[i]);
                result.Add(CreateSbom(values));
            }

            if (createLog)
                CreateLog(result.ToArray(), logFile, outputLoc, multipleLicenses);

            return result;
        }

        static string[] ReadSbomValue(string directory)
        {
            string[] output = new string[6];

            output = UrlCreator(Path.Combine(directory, "lic-src.url"));
            output[0] = VersionCreator(Path.Combine(directory, "VERSION"));
            output[2] = LicenseCreator(Path.Combine(directory, "LICENSETYPE"));

            string[] name = directory.Split(new char[] { '/', '\\' });
            output[3] = name[name.Length - 1];

            output[5] = SurlCreator(output, directory);

            return output;
        }

        public static string[] UrlCreator(string directory)
        {
            string[] output = new string[6];
            if (File.Exists(directory))
            {
                string[] lines = File.ReadAllLines(directory);
                string[] splitLine = lines[4].Split('=');

                output[1] = splitLine[splitLine.Length - 1];

                string[] splitUrl = splitLine[splitLine.Length - 1].Split("/");
                splitUrl[splitUrl.Length - 1] = String.Empty;

                foreach (string word in splitUrl)
                {
                    output[4] += "/" + word;
                }
                output[4] = output[4].Trim('/');
            }
            else
            {
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

        public static string LicenseCreator(string directory)
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

        static string SurlCreator(string[] input, string directory)
        {
            string[] output = input;

            if (File.Exists(Path.Combine(directory, "lic-src.url")) && File.Exists(Path.Combine(directory, "VERSION")))
            {
                output[5] = "pgk:" + output[4].Replace(".com", "") + "@" + output[2];
            }
            else
            {
                output[5] = String.Empty;
            }

            return output[5];
        }

        static void ConvertToCsvAndCreate(string filename, Sbom[] sbom, string directory, string seperator)
        {
            if (File.Exists(Path.Combine(directory, filename + ".csv")))
                File.Delete(Path.Combine(directory, filename + ".csv"));

            using (StreamWriter writer = new StreamWriter(Path.Combine(directory, filename + ".csv"), true))
            {
                writer.WriteLine($"0;Name;Version;Source of License;License;Source of Code;Purl;");

                for (int i = 0; i < sbom.Length; i++)
                {
                    writer.Write((i + 1) + seperator);
                    writer.Write(sbom[i].Directory + seperator);
                    writer.Write(sbom[i].License + seperator);
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
                    if (sbom[i].Version == String.Empty || sbom[i].Version == null)
                        Console.WriteLine($"There is no Version in {name}");
                    if (sbom[i].SourceOfCode == String.Empty || sbom[i].SourceOfCode == null)
                        Console.WriteLine($"There is no Url in {name}");
                    if (sbom[i].License == String.Empty || sbom[i].License == null)
                        Console.WriteLine($"There is no Licensetype in {name}");
                }
                else
                {
                    using (StreamWriter sw = new StreamWriter(Path.Combine(fileName, "log.txt"), true))
                    {
                        if (sbom[i].Version == String.Empty || sbom[i].Version == null)
                            sw.WriteLine($"There is no Version in {name}");
                        if (sbom[i].SourceOfCode == String.Empty || sbom[i].SourceOfCode == null)
                            sw.WriteLine($"There is no Url in {name}");
                        if (sbom[i].License == String.Empty || sbom[i].License == null)
                            sw.WriteLine($"There is no Licesne in {name}");
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
            using (StreamWriter sw = new(fileName))
            {
                sw.WriteLine("SPDXVersion: SPDX-2.2");
                sw.WriteLine("DataLicense: CC0-1.0");
                sw.WriteLine($"PackageName: {sbom.Directory}");
                sw.WriteLine($"PackageVersion: {sbom.Version}");
                sw.WriteLine($"PackageDownloadLocation: {sbom.SourceOfCode}");
                sw.WriteLine($"PackageLicenseDeclared: {sbom.License}");
                sw.WriteLine($"PackageLicenseConcluded: {sbom.License}");
                sw.WriteLine($"PackageLicenseInfoFromFiles: {sbom.SourceOfLicense}");
                sw.WriteLine($"PackageHomePage: {sbom.Purl}");
            }
        }

        static void ConvertToCsv(string filename, Sbom[] sbom, string directory, string[] csv, string seperator)
        {
            using (StreamWriter writer = new StreamWriter(Path.Combine(directory, filename + ".csv"), true))
            {

                for (int i = 0; i < sbom.Length; i++)
                {
                    writer.Write((i + csv.Length) + seperator);
                    writer.Write(sbom[i].Directory + seperator);
                    writer.Write(sbom[i].License + seperator);
                    writer.Write(sbom[i].SourceOfLicense + seperator);
                    writer.Write(sbom[i].Version + seperator);
                    writer.Write(sbom[i].SourceOfCode + seperator);
                    writer.Write(sbom[i].Purl + seperator);
                    writer.WriteLine();
                }

            }
        }

    }
}