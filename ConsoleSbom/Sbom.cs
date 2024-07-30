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
        private string _name;
        private string _purl;
        private string[] _license;

        public Sbom(){
            // GRGR: Array.Empty<string>() 
            _license = new string[0];
            _version = String.Empty;
            _sourceOfLicense = String.Empty;
            _sourceOfCode = String.Empty;
            _licenseType = String.Empty;
            _name = String.Empty;
            _purl = String.Empty;
        }

        // GRGR: use auto properties
        // GRGR: use initializers
        //  e.g. public string Name { get; set; } = string.Empty;
        public string Name
        {
            get { return _name; }
            set { _name = value; }
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

        public string[] License
        {
            get { return _license; }
            set { _license = value; }
        }
    }
}