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

                            Sbom[] sbom;

                            sbom = CreateSbomArray(args[0], optArgs[0], optArgs[1], args[3]);

                            bool tmp = false;

                            if (optArgs[2])
                            {
                                string[] csv;

                                if (File.Exists(Path.Combine(args[3], args[2] + ".csv")))
                                {
                                    csv = File.ReadAllLines(Path.Combine(args[3], args[2] + ".csv"));
                                    ConvertToCsv(args[2], sbom, args[3], csv);
                                }
                                else
                                    tmp = true;
                            }
                            else
                                tmp = true;

                            if (tmp)
                            {
                                if (args[1] == "csv")
                                    ConvertToCsvAndCreate(args[2], sbom, args[3]);
                                if (args[1] == "spdx")
                                    ConvertFromSbomToSpdx(args[2], sbom, args[3]);
                                if (args[1] == "all")
                                {
                                    ConvertToCsvAndCreate(args[2], sbom, args[3]);
                                    ConvertFromSbomToSpdx(args[2], sbom, args[3]);
                                }
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
                    Console.WriteLine("The fifth arg should be log if a log should be provided");
                    Console.WriteLine();
                    Console.WriteLine("The sixth arg should be file if the log should be provided in a file");
                    Console.WriteLine();
                    Console.WriteLine("The seventh arg should be add if the new csv should be added at the end of the old one");
                }
            }
            else
            {
                Console.WriteLine("Not enough parameter");
            }

        }

        static bool[] OptionalParameter(string[] input)
        {
            bool[] output = new bool[3];

            for (int i = 4; i < input.Length; i++)
            {
                if (input[i] == "log")
                    output[0] = true;

                if (input[i] == "file")
                    output[1] = true;

                if (input[i] == "add")
                    output[2] = true;
            }

            if (output[0])
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

        public static Sbom[] CreateSbomArray(string parentDirectory, bool createLog, bool logFile, string outputLoc)
        {
            int posForNewValue = 0;

            string[] directories = Directory.GetDirectories(parentDirectory);

            Sbom[] result = new Sbom[SbomLengthChecker(directories)];

            for (int i = 0; i < directories.Length; i++)
            {
                if (DirectoryChecker(directories[i]))
                {
                    string[] values = ReadSbomValue(directories[i]);
                    result[i] = CreateSbom(values);
                }
                else
                {
                    posForNewValue -= 1; // So the folder with other folders inside won't be counted;

                    string[] daughterDirectories1 = Directory.GetDirectories(directories[i]);

                    for (int j = 0; j < daughterDirectories1.Length; j++)
                    {
                        string[] values = ReadSbomValue(daughterDirectories1[j]);

                        posForNewValue++;
                        result[posForNewValue + i] = CreateSbom(values);

                    }
                }
            }

            if (createLog)
                CreateLog(result, logFile, outputLoc);

            return result;
        }

        static bool DirectoryChecker(string directoryToCheck)
        {
            if (File.Exists(Path.Combine(directoryToCheck, "lic-src.url")) || File.Exists(Path.Combine(directoryToCheck, "VERSION")) || File.Exists(Path.Combine(directoryToCheck, "LICENSETYPE")))
            {
                return true;
            }
            return false;
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

        static int SbomLengthChecker(string[] directories)
        {
            int output = 0;

            for (int i = 0; i < directories.Length; i++)
            {
                if (DirectoryChecker(directories[i]))
                {
                    output++;
                }
                else
                {
                    string[] tmp = Directory.GetDirectories(directories[i]);
                    output += SbomLengthChecker(tmp);
                }
            }

            return output;
        }

        static void ConvertToCsvAndCreate(string filename, Sbom[] sbom, string directory)
        {
            if (File.Exists(Path.Combine(directory, filename + ".csv")))
                File.Delete(Path.Combine(directory, filename + ".csv"));

            using (StreamWriter writer = new StreamWriter(Path.Combine(directory, filename + ".csv"), true))
            {
                writer.WriteLine($"0; Name; Version; Source of License; License; Source of Code; Purl;");

                for (int i = 0; i < sbom.Length; i++)
                {
                    writer.Write((i + 1) + ";");
                    writer.Write(sbom[i].Directory + ";");
                    writer.Write(sbom[i].License + ";");
                    writer.Write(sbom[i].SourceOfLicense + ";");
                    writer.Write(sbom[i].Version + ";");
                    writer.Write(sbom[i].SourceOfCode + ";");
                    writer.Write(sbom[i].Purl + ";");
                    writer.WriteLine();
                }

            }
        }

        static void CreateLog(Sbom[] sbom, bool logFile, string fileName)
        {
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
                    if (File.Exists(Path.Combine(fileName, "log.txt")))
                        File.Delete(Path.Combine(fileName, "log.txt"));

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

        static void ConvertToCsv(string filename, Sbom[] sbom, string directory, string[] csv)
        {
            using (StreamWriter writer = new StreamWriter(Path.Combine(directory, filename + ".csv"), true))
            {

                for (int i = 0; i < sbom.Length; i++)
                {
                    writer.Write((i + csv.Length) + ";");
                    writer.Write(sbom[i].Directory + ";");
                    writer.Write(sbom[i].License + ";");
                    writer.Write(sbom[i].SourceOfLicense + ";");
                    writer.Write(sbom[i].Version + ";");
                    writer.Write(sbom[i].SourceOfCode + ";");
                    writer.Write(sbom[i].Purl + ";");
                    writer.WriteLine();
                }

            }
        }

    }
}