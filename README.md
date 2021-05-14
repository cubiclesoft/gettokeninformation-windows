GetTokenInformation Windows API Command-Line Utility
====================================================

A complete, robust command-line utility to dump the contents of Windows security tokens using the GetTokenInformation() Windows API as JSON.  Released under a MIT or LGPL license.

Learn about security tokens, the GetTokenInformation() API, this tool, and much more:

[![Windows Security Objects:  A Crash Course + A Brand New Way to Start Processes on Microsoft Windows video](https://user-images.githubusercontent.com/1432111/118288197-0574ec00-b489-11eb-96e5-fab0f6149171.png)](https://www.youtube.com/watch?v=pmteqkbBfAY "Windows Security Objects:  A Crash Course + A Brand New Way to Start Processes on Microsoft Windows")

[![Donate](https://cubiclesoft.com/res/donate-shield.png)](https://cubiclesoft.com/donate/) [![Discord](https://img.shields.io/discord/777282089980526602?label=chat&logo=discord)](https://cubiclesoft.com/product-support/github/)

Features
--------

* Command-line action!
* Dumps the results of the GetTokenInformation() as JSON.  Easily consumed by most programming and scripting languages.
* Retrieve the token for any process or thread.  Can also find a token that has specific SIDs and privileges.
* Create and test custom tokens using the /createtoken option.
* Pre-built binaries using Visual Studio (statically linked C++ runtime, minimal file size of ~112K, direct Win32 API calls).
* Windows subsystem variant.
* Unicode support.
* Has a liberal open source license.  MIT or LGPL, your choice.
* Sits on GitHub for all of that pull request and issue tracker goodness to easily submit changes and ideas respectively.

Useful Information
------------------

Running the command with the `/?` option will display the options:

```
(C) 2021 CubicleSoft.  All Rights Reserved.

Syntax:  gettokeninformation [options]

Options:
        /v
        Verbose mode.

        /login
        Use a Windows credentials dialog to create and retrieve a token.
        Incompatible with '/pid', '/tid', '/usetoken', and '/createtoken'.

        /pid=ProcessID
        The process ID to retrieve token information from.
        Incompatible with '/login', '/tid', '/usetoken', and '/createtoken'.

        /tid=ThreadID
        The thread ID to retrieve token information from.
        Incompatible with '/login', '/pid', '/usetoken', and '/createtoken'.

        /usetoken=PIDorSIDsAndPrivileges
        Uses the primary token of the specified process ID,
        or a process matching specific comma-separated user/group SIDs
        and/or a process with specific privileges.
        Requires SeDebugPrivilege.
        Incompatible with '/login', '/pid', '/tid', and '/createtoken'.

        /createtokenwild=ProcessID
        The primary token of the specified process ID is used
        with '/createtoken' for wildcard parameters.

        /createtoken=Parameters
        Creates a primary token from scratch.
        Requires SeDebugPrivilege.
        Incompatible with '/login', '/pid', '/tid', and '/usetoken'.
        Uses an undocumented Windows kernel API.
        The 'Parameters' are semicolon separated:
                UserSID;
                GroupSID:Attr,GroupSID:Attr,...;
                Privilege:Attr,Privilege:Attr,...;
                OwnerSID;
                PrimaryGroupSID;
                DefaultDACL;
                SourceInHex:SourceLUID

        /raw
        Include retrieved hex encoded raw data.

        /file=OutputFile
        File to write the JSON output to instead of stdout.

        /c=TokenInfoClass
        A token information class to retrieve.
        Multiple /c options can be specified.
        Each 'TokenInfoClass' can be one of:
                TokenUser
                TokenGroups
                TokenPrivileges
                TokenOwner
                TokenPrimaryGroup
                TokenDefaultDacl
                TokenSource
                TokenType
                TokenImpersonationLevel
                TokenStatistics
                TokenRestrictedSids
                TokenSessionId
                TokenGroupsAndPrivileges
                TokenSessionReference
                TokenSandBoxInert
                TokenAuditPolicy
                TokenOrigin
                TokenElevationType
                TokenLinkedToken
                TokenElevation
                TokenHasRestrictions
                TokenAccessInformation
                TokenVirtualizationAllowed
                TokenVirtualizationEnabled
                TokenIntegrityLevel
                TokenUIAccess
                TokenMandatoryPolicy
                TokenLogonSid
                TokenIsAppContainer
                TokenCapabilities
                TokenAppContainerSid
                TokenAppContainerNumber
                TokenUserClaimAttributes
                TokenDeviceClaimAttributes
                TokenRestrictedUserClaimAttributes
                TokenRestrictedDeviceClaimAttributes
                TokenDeviceGroups
                TokenRestrictedDeviceGroups
                TokenSecurityAttributes
                TokenIsRestricted
                TokenProcessTrustLevel
                TokenPrivateNameSpace
                TokenSingletonAttributes
                TokenBnoIsolation
                TokenChildProcessFlags
                TokenIsLessPrivilegedAppContainer
                TokenIsSandboxed
                TokenOriginatingProcessTrustLevel
```

Example usage:

```
C:\>gettokeninformation /login
{"success": true,

"TokenUser": {"success": true, "info": {"sid": "S-1-5-21-1304824241-3403877634-2989090281-1005", "domain": "MY-PC", "account": "Bob", "type": 1, "attrs": 0}},

...
}

C:\>gettokeninformation /createtokenwild=1592 /createtoken=S-1-5-21-1304824241-3403877634-2989090281-1003;*;SeCreateTokenPrivilege:0,SeAssignPrimaryTokenPrivilege:3,SeTcbPrivilege:3;S-1-5-32-544;S-1-5-32-544;*;*
{"success": true,

"TokenUser": {"success": true, "info": {"sid": "S-1-5-21-1304824241-3403877634-2989090281-1003", "domain": "MY-PC", "account": "T2", "type": 1, "attrs": 0}},

"TokenGroups": {"success": true, "info": [{"sid": "S-1-16-16384", "domain": "Mandatory Label", "account": "System Mandatory Level", "type": 10, "attrs": 96},
{"sid": "S-1-1-0", "domain": "", "account": "Everyone", "type": 5, "attrs": 7},
{"sid": "S-1-5-32-545", "domain": "BUILTIN", "account": "Users", "type": 4, "attrs": 7},
{"sid": "S-1-5-6", "domain": "NT AUTHORITY", "account": "SERVICE", "type": 5, "attrs": 7},
{"sid": "S-1-2-1", "domain": "", "account": "CONSOLE LOGON", "type": 5, "attrs": 7},
{"sid": "S-1-5-11", "domain": "NT AUTHORITY", "account": "Authenticated Users", "type": 5, "attrs": 7},
{"sid": "S-1-5-15", "domain": "NT AUTHORITY", "account": "This Organization", "type": 5, "attrs": 7},
{"sid": "S-1-5-80-2014626298-1656748749-3847481816-918933055-2469338456", "domain": "NT SERVICE", "account": "UmRdpService", "type": 5, "attrs": 14},
{"sid": "S-1-5-5-0-84581", "domain": "NT AUTHORITY", "account": "LogonSessionId_0_84581", "type": 11, "attrs": 3221225487},
{"sid": "S-1-2-0", "domain": "", "account": "LOCAL", "type": 5, "attrs": 7},
{"sid": "S-1-5-32-544", "domain": "BUILTIN", "account": "Administrators", "type": 4, "attrs": 14}]},

"TokenPrivileges": {"success": true, "info": [{"luid": 2, "attrs": 0, "name": "SeCreateTokenPrivilege"},
{"luid": 3, "attrs": 3, "name": "SeAssignPrimaryTokenPrivilege"},
{"luid": 7, "attrs": 3, "name": "SeTcbPrivilege"}]},

"TokenOwner": {"success": true,
"info": {"sid": "S-1-5-32-544", "domain": "BUILTIN", "account": "Administrators", "type": 4}},

"TokenPrimaryGroup": {"success": true,
"info": {"sid": "S-1-5-32-544", "domain": "BUILTIN", "account": "Administrators", "type": 4}},

"TokenDefaultDacl": {"success": true, "info": "D:(A;;GA;;;SY)(A;;RC;;;OW)(A;;GA;;;S-1-5-80-2014626298-1656748749-3847481816-918933055-2469338456)"},

"TokenSource": {"success": true, "info": {"name": "4164766170692020", "id": 84583}},

...
}
```

The first command dumps out the current token.  The second command creates a token and then dumps it.

Windows Subsystem Variant
-------------------------

While `gettokeninformation.exe` is intended for use with console apps, `gettokeninformation-win.exe` is intended for detached console and GUI applications.  Starting `gettokeninformation.exe` in certain situations will briefly flash a console window before displaying the error message.  Calling `gettokeninformation-win.exe` instead will no longer show the console window.

There is one additional option specifically for `messagebox-win.exe` called `/attach` which attempts to attach to the console of the parent process (if any).

More Information
----------------

See the [GetTokenInformation() API documentation](https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-gettokeninformation) for details.

Related Tools
-------------

* [GetSIDInfo](https://github.com/cubiclesoft/getsidinfo-windows) - Dumps information about Windows Security Identifiers (SIDs) as JSON.
* [CreateProcess](https://github.com/cubiclesoft/createprocess-windows) - A powerful Windows API command-line utility that can start processes with all sorts of options including custom user tokens.
