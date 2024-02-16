---
layout: post
title: Windows Persistence Basics
date: 2023-11-25
categories: [Malware Development,Persistence]
tags: [persistence]     # TAG names should always be lowercase
---


In this post, we will discuss two basic Windows persistence techniques. Keep in mind that these methods are old and quite easily detectable, but serve as a good starting point to understanding persistence.

### Start folder

One of the oldest tricks in the book is copying our agent to the available user's startup folder. This technique is not only simple but can be executed in a medium integrity level.

To set up the persistence, we need to copy our binary to the current user's Startup folder, located at `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`. Alternatively, we may place a link file.

```
copy c:\Path\To\dropper.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
```

To verify if it works, we have to reboot the system, or sign out the current session and log in again.

### Registry run keys

The Windows Registry's run keys allow specific settings or configurations to be loaded automatically when the system starts up. These keys can also be used to execute specific programs.

There are two run keys that can be used, depending on the user's privileges:

- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`

- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`

The first key is used for settings that apply to the current user, while the second is used for all users. We can only modify the key in the HKLM registry hive if we have administrative privileges.

To execute this persistence maneuver, we need to add an entry to the run key, pointing to our executable. We can achieve this by using `reg add` 

```
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v MSUpdate /t REG_SZ /d c:\Path\To\dropper.exe /f 
```

In this command:

- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run is the registry key` being modified.
- `/v MSUpdate` specifies the name of the new entry.
- `/t REG_SZ` sets the type of the entry to a string.
- `/d c:\Path\To\dropper.exe` sets the data for the entry to the path of the executable.
- `/f forces` the command to overwrite any existing entry with the same name.

And we're done!
