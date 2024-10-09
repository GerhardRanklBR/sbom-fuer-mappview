namespace UpdateVersion
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 2)
            {
                string version = args[0];
                string file = args[1];
                string[] fileContent;

                if (file[1] != ':')
                {
                    file = Path.GetFullPath(file);
                }
                if (File.Exists(file))
                {
                    Console.WriteLine(version);
                    fileContent = File.ReadAllLines(file);
                    fileContent[21] = fileContent[21].Replace("6.0.0", version);
                    fileContent[31] = fileContent[31].Replace("6.0.0", version);

                    using (StreamWriter writer = new StreamWriter(file, false))
                    {
                        foreach (string line in fileContent)
                        {
                            writer.WriteLine(line);
                        }
                    }
                }
                else
                {
                    throw new Exception("File doesn't exist");
                }
            }
            else
            {
                throw new Exception("Wrong number of args");
            }
        }
    }
}
