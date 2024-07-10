using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ConsoleSBOM
{
    public class Sbom
    {
        private string _version;
        private string _sourceOfLicense;
        private string _sourceOfCode;
        private string _licenseType;
        private string _directory;
        private string _purl;
        private string _license;

        public string Directory
        {
            get { return _directory; }
            set { _directory = value; }
        }
        public string Version
        {
            get { return _version; }
            set { _version = value; }
        }

        public string SourceOfLicense
        {
            get { return _sourceOfLicense; }
            set { _sourceOfLicense = value; }
        }

        public string LicenseType
        {
            get { return _licenseType; }
            set { _licenseType = value; }
        }

        public string SourceOfCode
        {
            get { return _sourceOfCode; }
            set { _sourceOfCode = value; }
        }

        public string Purl
        {
            get { return _purl; }
            set { _purl = value; }
        }

        public string License
        {
            get { return _license; }
            set { _license = value; }
        }
    }
}
