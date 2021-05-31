using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Navigation;

namespace crypt
{
    class Program
    {
        private static void ProduceXML()
        {
            using (var crypt = RSACryptoServiceProvider.Create())
            {
                string secretkey = crypt.ToXmlString(true);
                Console.WriteLine("secretkey");
                Console.WriteLine(secretkey);
                using (StreamWriter sw = new StreamWriter(@"secretkey.xml"))
                {
                    sw.WriteLine(secretkey);
                }
                string publickey = crypt.ToXmlString(false);
                Console.WriteLine("publickey");
                Console.WriteLine(publickey);
                using (StreamWriter sw = new StreamWriter(@"publickey.xml"))
                {
                    sw.WriteLine(publickey);
                }
            }
        }
        [STAThread]
        static void Main(string[] args)
        {
            if (args.Contains("xml"))
            {
                if (args.Length > 1)
                {
                    Console.WriteLine("too many args for verb xml");
                    return;
                }
                ProduceXML();
                return;
            }
            if (args.Contains("sign"))
            {
                int input_idx = Array.IndexOf(args, "-input");
                string input_path;
                if (input_idx > -1 && input_idx < args.Length - 1 && !args[input_idx + 1].StartsWith("-"))
                {
                    input_path = args[input_idx + 1];
                } else
                {
                    Console.WriteLine("-input missing");
                    return;
                }
                int output_idx = Array.IndexOf(args, "-output");
                string output_path;
                if (output_idx > -1 && output_idx < args.Length - 1 && !args[output_idx + 1].StartsWith("-"))
                {
                    output_path = args[output_idx + 1];
                }
                else
                {
                    Console.WriteLine("-output missing");
                    return;
                }
                int secretkey_idx = Array.IndexOf(args, "-secretkey");
                string secretkey_path;
                if (secretkey_idx > -1 && secretkey_idx < args.Length - 1 && !args[secretkey_idx + 1].StartsWith("-"))
                {
                    secretkey_path = args[secretkey_idx + 1];
                }
                else
                {
                    Console.WriteLine("-secretkey missing");
                    return;
                }
                if (args.Length > 7)
                {
                    Console.WriteLine("too many args for verb sign");
                    return;
                }
                Console.WriteLine("sign secretkey={3} input={0} output={1} of {2} args", input_path, output_path, args.Length, secretkey_path);
                Sign(secretkey_path, input_path, output_path);
                return;
            }
            if (args.Contains("verify"))
            {
                int input_idx = Array.IndexOf(args, "-input");
                string input_path;
                if (input_idx > -1 && input_idx < args.Length - 1 && !args[input_idx + 1].StartsWith("-"))
                {
                    input_path = args[input_idx + 1];
                }
                else
                {
                    Console.WriteLine("-input missing");
                    return;
                }
                int publickey_idx = Array.IndexOf(args, "-publickey");
                string publickey_path;
                if (publickey_idx > -1 && publickey_idx < args.Length - 1 && !args[publickey_idx + 1].StartsWith("-"))
                {
                    publickey_path = args[publickey_idx + 1];
                }
                else
                {
                    Console.WriteLine("-publickey missing");
                    return;
                }
                int signature_idx = Array.IndexOf(args, "-signature");
                string signature_path;
                if (signature_idx > -1 && signature_idx < args.Length - 1 && !args[signature_idx + 1].StartsWith("-"))
                {
                    signature_path = args[signature_idx + 1];
                }
                else
                {
                    Console.WriteLine("-signature missing");
                    return;
                }
                if (args.Length > 7)
                {
                    Console.WriteLine("too many args for verb verify");
                    return;
                }
                Console.WriteLine("verify pubkey={0} input={1} signature={2} of {3} args", publickey_path, input_path, signature_path, args.Length);
                bool verified = VerifySigned(input_path, publickey_path, signature_path);
                Console.WriteLine("verified: " + (verified ? "Yes" : "No"));
                return;
            }

            if (args.Contains("run-in-memory"))
            {
                int input_idx = Array.IndexOf(args, "-input");
                string input_path;
                if (input_idx > -1 && input_idx < args.Length - 1 && !args[input_idx + 1].StartsWith("-"))
                {
                    input_path = args[input_idx + 1];
                }
                else
                {
                    Console.WriteLine("-input missing");
                    return;
                }
                int publickey_idx = Array.IndexOf(args, "-publickey");
                string publickey_path;
                if (publickey_idx > -1 && publickey_idx < args.Length - 1 && !args[publickey_idx + 1].StartsWith("-"))
                {
                    publickey_path = args[publickey_idx + 1];
                }
                else
                {
                    Console.WriteLine("-publickey missing");
                    return;
                }
                int signature_idx = Array.IndexOf(args, "-signature");
                string signature_path;
                if (signature_idx > -1 && signature_idx < args.Length - 1 && !args[signature_idx + 1].StartsWith("-"))
                {
                    signature_path = args[signature_idx + 1];
                }
                else
                {
                    Console.WriteLine("-signature missing");
                    return;
                }
                if (args.Length > 7)
                {
                    Console.WriteLine("too many args for verb run-in-memory");
                    return;
                }
                Console.WriteLine("run-in-memory pubkey={0} input={1} signature={2} of {3} args", publickey_path, input_path, signature_path, args.Length);
                RunSigned(input_path, publickey_path, signature_path);
                return;
            }
            Console.WriteLine("valid verbs are only: xml | sign | verify | run-in-memory");
        }
        private static void Sign(string secretkey_path, string input_path, string output_path)
        {
            using (var crypt = RSA.Create())
            {
                using (StreamReader sr = new StreamReader(secretkey_path))
                {
                    string secret = sr.ReadToEnd();
                    crypt.FromXmlString(secret);
                }
                byte[] exe = File.ReadAllBytes(input_path);
                byte[] crypto_exe = crypt.SignData(exe, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                File.WriteAllBytes(output_path, crypto_exe);
            }
        }
        private static bool VerifySigned(string input_path, string publickey_path, string signature_path)
        {
            byte[] bytes = File.ReadAllBytes(input_path);
            using (var crypt = RSA.Create())
            {
                using (StreamReader sr = new StreamReader(publickey_path))
                {
                    string publickkey = sr.ReadToEnd();
                    crypt.FromXmlString(publickkey);
                }
                byte[] signed = File.ReadAllBytes(signature_path);
                bool verified = crypt.VerifyData(bytes, signed, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
                return verified;
            }
        }
        private static void RunSigned(string input_path, string publickey_path, string signature_path)
        {
            bool verified = VerifySigned(input_path, publickey_path, signature_path);
            if (!verified)
            {
                Console.WriteLine("Not verified! Can't launch!");
                return;
            }
            Console.WriteLine("running " + input_path + " in memory");
            byte[] bytes = File.ReadAllBytes(input_path);
            Assembly assembly = Assembly.Load(bytes);

            var app = typeof(Application);

            var field = app.GetField("_resourceAssembly", BindingFlags.NonPublic | BindingFlags.Static);
            field.SetValue(null, assembly);

            var helper = typeof(BaseUriHelper);
            var property = helper.GetProperty("ResourceAssembly", BindingFlags.NonPublic | BindingFlags.Static);
            property.SetValue(null, assembly, null);


            try
            {
                assembly.EntryPoint.Invoke(null, new object[0]);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }
    }
}
