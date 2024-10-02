using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleSBOM
{
    public class Sbom
    {
        public string Name { get; set; } = string.Empty;

        public string Version { get; set; } = string.Empty;

        public string SourceOfLicense { get; set; } = string.Empty;

        public string LicenseType { get; set; } = string.Empty;

        public string SourceOfCode { get; set; } = string.Empty;

        public string Purl { get; set; } = string.Empty;

        public string[] License { get; set; } = Array.Empty<string>();

        public string Path { get; set; } = string.Empty;
    }
}