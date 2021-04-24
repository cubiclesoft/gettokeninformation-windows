// A simple program to dump token information as consumable JSON.
//
// (C) 2021 CubicleSoft.  All Rights Reserved.

#define UNICODE
#define _UNICODE
#define _CRT_SECURE_NO_WARNINGS

#ifdef _MBCS
#undef _MBCS
#endif

#define _CRT_NONSTDC_NO_WARNINGS

#include <cstdio>
#include <cstdlib>
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#define _NTDEF_
#include <ntsecapi.h>
#include <wincred.h>
#include <objbase.h>
#include <sddl.h>
#include <tchar.h>

#include "utf8/utf8_util.h"
#include "utf8/utf8_file_dir.h"
#include "utf8/utf8_mixed_var.h"
#include "json/json_serializer.h"
#include "templates/static_wc_mixed_var.h"
#include "templates/shared_lib.h"

const char *GxTokenClasses[] = {
	NULL, "TokenUser", "TokenGroups", "TokenPrivileges", "TokenOwner", "TokenPrimaryGroup",
	"TokenDefaultDacl", "TokenSource", "TokenType", "TokenImpersonationLevel", "TokenStatistics",
	"TokenRestrictedSids", "TokenSessionId", "TokenGroupsAndPrivileges", "TokenSessionReference", "TokenSandBoxInert",
	"TokenAuditPolicy", "TokenOrigin", "TokenElevationType", "TokenLinkedToken", "TokenElevation",
	"TokenHasRestrictions", "TokenAccessInformation", "TokenVirtualizationAllowed", "TokenVirtualizationEnabled", "TokenIntegrityLevel",
	"TokenUIAccess", "TokenMandatoryPolicy", "TokenLogonSid", "TokenIsAppContainer", "TokenCapabilities",
	"TokenAppContainerSid", "TokenAppContainerNumber", "TokenUserClaimAttributes", "TokenDeviceClaimAttributes", "TokenRestrictedUserClaimAttributes",
	"TokenRestrictedDeviceClaimAttributes", "TokenDeviceGroups", "TokenRestrictedDeviceGroups", "TokenSecurityAttributes", "TokenIsRestricted",
	"TokenProcessTrustLevel", "TokenPrivateNameSpace", "TokenSingletonAttributes", "TokenBnoIsolation", "TokenChildProcessFlags",
	"TokenIsLessPrivilegedAppContainer", "TokenIsSandboxed", "TokenOriginatingProcessTrustLevel"
};

const size_t GxNumTokenClasses = sizeof(GxTokenClasses) / sizeof(char *);

#ifdef SUBSYSTEM_WINDOWS
// If the caller is a console application and is waiting for this application to complete, then attach to the console.
void InitVerboseMode(void)
{
	if (::AttachConsole(ATTACH_PARENT_PROCESS))
	{
		if (::GetStdHandle(STD_OUTPUT_HANDLE) != INVALID_HANDLE_VALUE)
		{
			freopen("CONOUT$", "w", stdout);
			setvbuf(stdout, NULL, _IONBF, 0);
		}

		if (::GetStdHandle(STD_ERROR_HANDLE) != INVALID_HANDLE_VALUE)
		{
			freopen("CONOUT$", "w", stderr);
			setvbuf(stderr, NULL, _IONBF, 0);
		}
	}
}
#endif

void DumpSyntax(TCHAR *currfile)
{
#ifdef SUBSYSTEM_WINDOWS
	InitVerboseMode();
#endif

	_tprintf(_T("(C) 2021 CubicleSoft.  All Rights Reserved.\n\n"));

	_tprintf(_T("Syntax:  %s [options]\n\n"), currfile);

	_tprintf(_T("Options:\n"));

	_tprintf(_T("\t/v\n\
\tVerbose mode.\n\
\n\
\t/login\n\
\tUse a Windows credentials dialog to create and retrieve a token.\n\
\tIncompatible with '/pid', '/tid', '/usetoken', and '/createtoken'.\n\
\n\
\t/pid=ProcessID\n\
\tThe process ID to retrieve token information from.\n\
\tIncompatible with '/login', '/tid', '/usetoken', and '/createtoken'.\n\
\n\
\t/tid=ThreadID\n\
\tThe thread ID to retrieve token information from.\n\
\tIncompatible with '/login', '/pid', '/usetoken', and '/createtoken'.\n\
\n\
\t/usetoken=PIDorSIDsAndPrivileges\n\
\tUses the primary token of the specified process ID,\n\
\tor a process matching specific comma-separated user/group SIDs\n\
\tand/or a process with specific privileges.\n\
\tRequires SeDebugPrivilege.\n\
\tIncompatible with '/login', '/pid', '/tid', and '/createtoken'.\n\
\n\
\t/createtokenwild=ProcessID\n\
\tThe primary token of the specified process ID is used\n\
\twith '/createtoken' for wildcard parameters.\n\
\n\
\t/createtoken=Parameters\n\
\tCreates a primary token from scratch.\n\
\tRequires SeDebugPrivilege.\n\
\tIncompatible with '/login', '/pid', '/tid', and '/usetoken'.\n\
\tUses an undocumented Windows kernel API.\n\
\tThe 'Parameters' are semicolon separated:\n\
\t\tUserSID;\n\
\t\tGroupSID:Attr,GroupSID:Attr,...;\n\
\t\tPrivilege:Attr,Privilege:Attr,...;\n\
\t\tOwnerSID;\n\
\t\tPrimaryGroupSID;\n\
\t\tDefaultDACL;\n\
\t\tSourceInHex:SourceLUID\n\
\n\
\t/raw\n\
\tInclude retrieved hex encoded raw data.\n\
\n\
\t/file=OutputFile\n\
\tFile to write the JSON output to instead of stdout.\n\
\n\
\t/c=TokenInfoClass\n\
\tA token information class to retrieve.\n\
\tMultiple /c options can be specified.\n\
\tEach 'TokenInfoClass' can be one of:\n"));

	size_t x;
	for (x = 1; x < GxNumTokenClasses; x++)
	{
		printf("\t\t%s\n", GxTokenClasses[x]);
	}

	printf("\n");

#ifdef SUBSYSTEM_WINDOWS
	_tprintf(_T("\t/attach\n"));
	_tprintf(_T("\tAttempt to attach to a parent console if it exists.\n\n"));
#endif
}


bool SetThreadProcessPrivilege(LPCWSTR PrivilegeName, bool Enable)
{
	HANDLE Token;
	TOKEN_PRIVILEGES TokenPrivs;
	LUID TempLuid;
	bool Result;

	if (!::LookupPrivilegeValueW(NULL, PrivilegeName, &TempLuid))  return false;

	if (!::OpenThreadToken(::GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &Token))
	{
		if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))  return false;
	}

	TokenPrivs.PrivilegeCount = 1;
	TokenPrivs.Privileges[0].Luid = TempLuid;
	TokenPrivs.Privileges[0].Attributes = (Enable ? SE_PRIVILEGE_ENABLED : 0);

	Result = (::AdjustTokenPrivileges(Token, FALSE, &TokenPrivs, 0, NULL, NULL) && ::GetLastError() == ERROR_SUCCESS);

	::CloseHandle(Token);

	return Result;
}

void DumpOutput(CubicleSoft::UTF8::File &OutputFile, CubicleSoft::JSON::Serializer &OutputJSON)
{
	size_t y;

	if (OutputFile.IsOpen())  OutputFile.Write((std::uint8_t *)OutputJSON.GetBuffer(), OutputJSON.GetCurrPos(), y);
	else  printf("%s", OutputJSON.GetBuffer());

	OutputJSON.ResetPos();
}

struct SidInfo {
	PSID MxSid;
	TCHAR MxDomainName[1024];
	TCHAR MxAccountName[1024];
	SID_NAME_USE MxSidType;
};

bool DumpSid(CubicleSoft::UTF8::File &OutputFile, CubicleSoft::JSON::Serializer &OutputJSON, const char *key, PSID sid, bool closeobj = true, bool wrapsplit = true)
{
	LPTSTR tempstrsid = NULL;
	CubicleSoft::UTF8::UTF8MixedVar<char[8192]> TempVar;
	SidInfo TempSidInfo;
	DWORD acctbuffersize, domainbuffersize;

	if (!::ConvertSidToStringSid(sid, &tempstrsid))  return false;

	if (wrapsplit)  OutputJSON.SetValSplitter(",\n");
	OutputJSON.StartObject(key);
	OutputJSON.SetValSplitter(", ");

	// Basic information.
	TempVar.SetUTF8(tempstrsid);
	OutputJSON.AppendStr("sid", TempVar.GetStr());
	::LocalFree(tempstrsid);
	OutputJSON.SetValSplitter(", ");

	acctbuffersize = sizeof(TempSidInfo.MxAccountName) / sizeof(TCHAR);
	domainbuffersize = sizeof(TempSidInfo.MxDomainName) / sizeof(TCHAR);
	if (::LookupAccountSid(NULL, sid, TempSidInfo.MxAccountName, &acctbuffersize, TempSidInfo.MxDomainName, &domainbuffersize, &TempSidInfo.MxSidType))
	{
		TempVar.SetUTF8(TempSidInfo.MxDomainName);
		OutputJSON.AppendStr("domain", TempVar.GetStr());

		TempVar.SetUTF8(TempSidInfo.MxAccountName);
		OutputJSON.AppendStr("account", TempVar.GetStr());

		OutputJSON.AppendUInt("type", TempSidInfo.MxSidType);
	}

	if (closeobj)
	{
		DumpOutput(OutputFile, OutputJSON);

		OutputJSON.EndObject();
	}

	return true;
}

void DumpSidAndAttributes(CubicleSoft::UTF8::File &OutputFile, CubicleSoft::JSON::Serializer &OutputJSON, const char *key, SID_AND_ATTRIBUTES &sidattrs, bool wrapsplit = true)
{
	if (!DumpSid(OutputFile, OutputJSON, key, sidattrs.Sid, false, wrapsplit))  return;

	OutputJSON.AppendUInt("attrs", sidattrs.Attributes);

	DumpOutput(OutputFile, OutputJSON);

	OutputJSON.EndObject();
}

void DumpLuid(CubicleSoft::JSON::Serializer &OutputJSON, const char *key, LUID &luid)
{
	OutputJSON.AppendUInt(key, ((std::uint64_t)(DWORD)luid.HighPart << 32) | (std::uint64_t)luid.LowPart);
}

void DumpLuidAndAttributes(CubicleSoft::UTF8::File &OutputFile, CubicleSoft::JSON::Serializer &OutputJSON, const char *key, LUID_AND_ATTRIBUTES &luidattrs, bool closeobj = true)
{
	OutputJSON.SetValSplitter(",\n");
	OutputJSON.StartObject(key);
	OutputJSON.SetValSplitter(", ");

	DumpLuid(OutputJSON, "luid", luidattrs.Luid);

	OutputJSON.AppendUInt("attrs", luidattrs.Attributes);

	if (closeobj)
	{
		DumpOutput(OutputFile, OutputJSON);

		OutputJSON.EndObject();
	}
}

void DumpPrivilege(CubicleSoft::UTF8::File &OutputFile, CubicleSoft::JSON::Serializer &OutputJSON, LUID_AND_ATTRIBUTES &luidattrs)
{
	char buffer[256];
	DWORD buffersize = sizeof(buffer);

	DumpLuidAndAttributes(OutputFile, OutputJSON, NULL, luidattrs, false);

	if (::LookupPrivilegeNameA(NULL, &luidattrs.Luid, (LPSTR)buffer, &buffersize))  OutputJSON.AppendStr("name", buffer);

	DumpOutput(OutputFile, OutputJSON);

	OutputJSON.EndObject();
}

void DumpHexData(CubicleSoft::UTF8::File &OutputFile, CubicleSoft::JSON::Serializer &OutputJSON, const char *key, const std::uint8_t *buffer, size_t buffersize)
{
	std::uint8_t val, val2;
	char tempbuffer[1024];
	size_t x, x2 = 0, y2 = sizeof(tempbuffer);

	OutputJSON.StartStr(key);

	for (x = 0; x < buffersize; x++)
	{
		val = buffer[x];

		val2 = val / 16;
		tempbuffer[x2++] = (char)(val2 > 9 ? val2 - 10 + 'A' : val2 + '0');

		val2 = val % 16;
		tempbuffer[x2++] = (char)(val2 > 9 ? val2 - 10 + 'A' : val2 + '0');

		if (x2 >= y2)
		{
			if (!OutputJSON.AppendStr(tempbuffer, x2))
			{
				DumpOutput(OutputFile, OutputJSON);

				OutputJSON.AppendStr(tempbuffer, x2);
			}

			x2 = 0;
		}
	}

	DumpOutput(OutputFile, OutputJSON);

	if (x2)  OutputJSON.AppendStr(tempbuffer, x2);

	OutputJSON.EndStr();
}

void DumpWinError(CubicleSoft::JSON::Serializer &OutputJSON, DWORD winerror)
{
	LPTSTR errmsg = NULL;
	CubicleSoft::UTF8::UTF8MixedVar<char[8192]> TempVar;

	::FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, winerror, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&errmsg, 0, NULL);

	if (errmsg == NULL)  OutputJSON.AppendStr("winerror", "Unknown Windows error message.");
	else
	{
		TempVar.SetUTF8(errmsg);
		OutputJSON.AppendStr("winerror", TempVar.GetStr());

		::LocalFree(errmsg);
	}
}

void DumpTokenInformation(CubicleSoft::UTF8::File &OutputFile, CubicleSoft::JSON::Serializer &OutputJSON, bool classesused, bool *classes, bool rawdata, HANDLE tokenhandle, size_t Depth)
{
	size_t x, x2;
	LPVOID infobuffer = NULL;
	DWORD infobuffersize = 0, infobuffersize2;
	BOOL result, dumprawdata;
	DWORD winerror;

	// Retrieve all the juicy details about the token.
	for (x = 1; x < GxNumTokenClasses; x++)
	{
		if (!classesused || classes[x])
		{
			if (Depth > 1)  OutputJSON.SetValSplitter(",\n\n\t");
			else  OutputJSON.SetValSplitter(",\n\n");
			OutputJSON.StartObject(GxTokenClasses[x]);
			OutputJSON.SetValSplitter(", ");

			// Resize until the buffer is big enough.
			while (!(result = ::GetTokenInformation(tokenhandle, (TOKEN_INFORMATION_CLASS)x, infobuffer, infobuffersize, &infobuffersize2)) && (winerror = ::GetLastError()) == ERROR_INSUFFICIENT_BUFFER)
			{
				if (infobuffer != NULL)  ::LocalFree(infobuffer);

				infobuffer = (LPVOID)::LocalAlloc(LMEM_FIXED, infobuffersize2);
				if (infobuffer != NULL)  infobuffersize = infobuffersize2;
				else
				{
					infobuffersize = 0;

					winerror = ::GetLastError();

					break;
				}
			}

			// Retry with an exact size.  TokenLinkedToken, for example, returns ERROR_BAD_LENGTH.
			if (!result && winerror == ERROR_BAD_LENGTH && infobuffersize2 > 0)
			{
				result = ::GetTokenInformation(tokenhandle, (TOKEN_INFORMATION_CLASS)x, infobuffer, infobuffersize2, &infobuffersize2);
				if (!result)  winerror = ::GetLastError();
			}

			if (!result)
			{
				OutputJSON.AppendBool("success", false);
				OutputJSON.AppendStr("error", "Unable to get token information.");
				OutputJSON.AppendStr("errorcode", "get_token_information_failed");
				DumpWinError(OutputJSON, winerror);
				OutputJSON.AppendUInt("winerrorcode", winerror);
			}
			else if (infobuffer == NULL)
			{
				OutputJSON.AppendBool("success", false);
				OutputJSON.AppendStr("error", "Unable to allocate sufficient space for token information.");
				OutputJSON.AppendStr("errorcode", "local_alloc_failed");
				DumpWinError(OutputJSON, winerror);
				OutputJSON.AppendUInt("winerrorcode", winerror);
			}
			else
			{
				OutputJSON.AppendBool("success", true);

				dumprawdata = rawdata;

				switch (x)
				{
					case TokenUser:
					{
						DumpSidAndAttributes(OutputFile, OutputJSON, "info", ((PTOKEN_USER)infobuffer)->User, false);

						break;
					}
					case TokenGroups:
					case TokenRestrictedSids:
					case TokenLogonSid:
					case TokenCapabilities:
					case TokenDeviceGroups:
					case TokenRestrictedDeviceGroups:
					{
						OutputJSON.StartArray("info");

						for (x2 = 0; x2 < ((PTOKEN_GROUPS)infobuffer)->GroupCount; x2++)
						{
							DumpSidAndAttributes(OutputFile, OutputJSON, NULL, ((PTOKEN_GROUPS)infobuffer)->Groups[x2]);
						}

						OutputJSON.EndArray();

						break;
					}
					case TokenPrivileges:
					{
						OutputJSON.StartArray("info");

						for (x2 = 0; x2 < ((PTOKEN_PRIVILEGES)infobuffer)->PrivilegeCount; x2++)
						{
							DumpPrivilege(OutputFile, OutputJSON, ((PTOKEN_PRIVILEGES)infobuffer)->Privileges[x2]);
						}

						OutputJSON.EndArray();

						break;
					}
					case TokenOwner:
					{
						DumpSid(OutputFile, OutputJSON, "info", ((PTOKEN_OWNER)infobuffer)->Owner);

						break;
					}
					case TokenPrimaryGroup:
					{
						DumpSid(OutputFile, OutputJSON, "info", ((PTOKEN_PRIMARY_GROUP)infobuffer)->PrimaryGroup);

						break;
					}
					case TokenDefaultDacl:
					{
						SECURITY_DESCRIPTOR sd;
						LPTSTR tempsddl;

						if (::InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION) && ::SetSecurityDescriptorDacl(&sd, TRUE, ((PTOKEN_DEFAULT_DACL)infobuffer)->DefaultDacl, TRUE) && ::ConvertSecurityDescriptorToStringSecurityDescriptor(&sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &tempsddl, NULL))
						{
							CubicleSoft::UTF8::UTF8MixedVar<char[8192]> TempVar;

							TempVar.SetUTF8(tempsddl);
							OutputJSON.AppendStr("info", TempVar.GetStr());

							::LocalFree(tempsddl);
						}
						else
						{
							dumprawdata = true;
						}

						break;
					}
					case TokenSource:
					{
						OutputJSON.StartObject("info");

						DumpHexData(OutputFile, OutputJSON, "name", (std::uint8_t *)(((PTOKEN_SOURCE)infobuffer)->SourceName), TOKEN_SOURCE_LENGTH);
						DumpLuid(OutputJSON, "id", ((PTOKEN_SOURCE)infobuffer)->SourceIdentifier);

						OutputJSON.EndObject();

						break;
					}
					case TokenStatistics:
					{
						OutputJSON.StartObject("info");

						DumpLuid(OutputJSON, "token_id", ((PTOKEN_STATISTICS)infobuffer)->TokenId);
						DumpLuid(OutputJSON, "auth_id", ((PTOKEN_STATISTICS)infobuffer)->AuthenticationId);
						OutputJSON.AppendUInt("expires", ((PTOKEN_STATISTICS)infobuffer)->ExpirationTime.QuadPart);
						OutputJSON.AppendUInt("token_type", ((PTOKEN_STATISTICS)infobuffer)->TokenType);
						OutputJSON.AppendUInt("impersonation_level", ((PTOKEN_STATISTICS)infobuffer)->ImpersonationLevel);
						OutputJSON.AppendUInt("dynamic_charged", ((PTOKEN_STATISTICS)infobuffer)->DynamicCharged);
						OutputJSON.AppendUInt("dynamic_avail", ((PTOKEN_STATISTICS)infobuffer)->DynamicAvailable);
						OutputJSON.AppendUInt("num_groups", ((PTOKEN_STATISTICS)infobuffer)->GroupCount);
						OutputJSON.AppendUInt("num_privileges", ((PTOKEN_STATISTICS)infobuffer)->PrivilegeCount);
						DumpLuid(OutputJSON, "modified_id", ((PTOKEN_STATISTICS)infobuffer)->ModifiedId);

						OutputJSON.EndObject();

						break;
					}
					case TokenGroupsAndPrivileges:
					{
						OutputJSON.StartObject("info");

						OutputJSON.StartArray("sids");

						for (x2 = 0; x2 < ((PTOKEN_GROUPS_AND_PRIVILEGES)infobuffer)->SidCount; x2++)
						{
							DumpSidAndAttributes(OutputFile, OutputJSON, NULL, ((PTOKEN_GROUPS_AND_PRIVILEGES)infobuffer)->Sids[x2]);
						}

						OutputJSON.EndArray();

						OutputJSON.StartArray("restricted_sids");

						for (x2 = 0; x2 < ((PTOKEN_GROUPS_AND_PRIVILEGES)infobuffer)->RestrictedSidCount; x2++)
						{
							DumpSidAndAttributes(OutputFile, OutputJSON, NULL, ((PTOKEN_GROUPS_AND_PRIVILEGES)infobuffer)->RestrictedSids[x2]);
						}

						OutputJSON.EndArray();

						OutputJSON.StartArray("privileges");

						for (x2 = 0; x2 < ((PTOKEN_GROUPS_AND_PRIVILEGES)infobuffer)->PrivilegeCount; x2++)
						{
							DumpPrivilege(OutputFile, OutputJSON, ((PTOKEN_GROUPS_AND_PRIVILEGES)infobuffer)->Privileges[x2]);
						}

						OutputJSON.EndArray();

						DumpLuid(OutputJSON, "auth_id", ((PTOKEN_GROUPS_AND_PRIVILEGES)infobuffer)->AuthenticationId);

						OutputJSON.EndObject();

						break;

					}
					case TokenOrigin:
					{
						DumpLuid(OutputJSON, "info", ((PTOKEN_ORIGIN)infobuffer)->OriginatingLogonSession);

						break;
					}
					case TokenLinkedToken:
					{
						OutputJSON.StartObject("info");

						if (Depth >= 2)  OutputJSON.AppendBool("success", false);
						else
						{
							OutputJSON.AppendBool("success", true);

							DumpTokenInformation(OutputFile, OutputJSON, classesused, classes, rawdata, ((PTOKEN_LINKED_TOKEN)infobuffer)->LinkedToken, Depth + 1);
						}

						::CloseHandle(((PTOKEN_LINKED_TOKEN)infobuffer)->LinkedToken);

						OutputJSON.EndObject();

						break;
					}
					case TokenAccessInformation:
					{
						OutputJSON.StartObject("info");

						OutputJSON.StartArray("sids");

						for (x2 = 0; x2 < ((PTOKEN_ACCESS_INFORMATION)infobuffer)->SidHash->SidCount; x2++)
						{
							DumpSidAndAttributes(OutputFile, OutputJSON, NULL, ((PTOKEN_ACCESS_INFORMATION)infobuffer)->SidHash->SidAttr[x2]);
						}

						OutputJSON.EndArray();

						OutputJSON.StartArray("restricted_sids");

						for (x2 = 0; x2 < ((PTOKEN_ACCESS_INFORMATION)infobuffer)->RestrictedSidHash->SidCount; x2++)
						{
							DumpSidAndAttributes(OutputFile, OutputJSON, NULL, ((PTOKEN_ACCESS_INFORMATION)infobuffer)->RestrictedSidHash->SidAttr[x2]);
						}

						OutputJSON.EndArray();

						OutputJSON.StartArray("privileges");

						for (x2 = 0; x2 < ((PTOKEN_ACCESS_INFORMATION)infobuffer)->Privileges->PrivilegeCount; x2++)
						{
							DumpPrivilege(OutputFile, OutputJSON, ((PTOKEN_ACCESS_INFORMATION)infobuffer)->Privileges->Privileges[x2]);
						}

						OutputJSON.EndArray();

						DumpLuid(OutputJSON, "auth_id", ((PTOKEN_ACCESS_INFORMATION)infobuffer)->AuthenticationId);
						OutputJSON.AppendUInt("token_type", ((PTOKEN_ACCESS_INFORMATION)infobuffer)->TokenType);
						OutputJSON.AppendUInt("impersonation_level", ((PTOKEN_ACCESS_INFORMATION)infobuffer)->ImpersonationLevel);
						OutputJSON.AppendUInt("mandatory_policy", ((PTOKEN_ACCESS_INFORMATION)infobuffer)->MandatoryPolicy.Policy);
						OutputJSON.AppendUInt("flags", ((PTOKEN_ACCESS_INFORMATION)infobuffer)->Flags);
						OutputJSON.AppendUInt("app_container_num", ((PTOKEN_ACCESS_INFORMATION)infobuffer)->AppContainerNumber);
						DumpSid(OutputFile, OutputJSON, "package_sid", ((PTOKEN_ACCESS_INFORMATION)infobuffer)->PackageSid);

						OutputJSON.StartArray("capabilities");

						for (x2 = 0; x2 < ((PTOKEN_ACCESS_INFORMATION)infobuffer)->CapabilitiesHash->SidCount; x2++)
						{
							DumpSidAndAttributes(OutputFile, OutputJSON, NULL, ((PTOKEN_ACCESS_INFORMATION)infobuffer)->CapabilitiesHash->SidAttr[x2]);
						}

						OutputJSON.EndArray();

						DumpSid(OutputFile, OutputJSON, "trust_level_sid", ((PTOKEN_ACCESS_INFORMATION)infobuffer)->TrustLevelSid);

						// Not sure how to handle the "opaque" SecurityAttributes member.

						OutputJSON.EndObject();

						break;
					}
					case TokenIntegrityLevel:
					{
						DumpSidAndAttributes(OutputFile, OutputJSON, "info", ((PTOKEN_MANDATORY_LABEL)infobuffer)->Label, false);

						break;
					}
					case TokenAppContainerSid:
					{
						DumpSid(OutputFile, OutputJSON, "info", ((PTOKEN_APPCONTAINER_INFORMATION)infobuffer)->TokenAppContainer, true, false);

						break;
					}

					// DWORD cases.
					case TokenType:
					case TokenImpersonationLevel:
					case TokenSessionId:
					case TokenSandBoxInert:
					case TokenElevationType:
					case TokenElevation:  // Described as a structure but only contains a DWORD.
					case TokenHasRestrictions:  // Oddly this is returned as one byte of data rather than a DWORD size (possible bug in GetTokenInformation()?).
					case TokenVirtualizationAllowed:
					case TokenVirtualizationEnabled:
					case TokenUIAccess:
					case TokenMandatoryPolicy:  // Described as a structure but only contains a DWORD.
					case TokenIsAppContainer:
					case TokenAppContainerNumber:
					{
						OutputJSON.AppendUInt("info", *((DWORD *)infobuffer));

						break;
					}

					// Dump everything else as-is.
					default:
					{
						dumprawdata = true;

						break;
					}
				}

				if (dumprawdata)  DumpHexData(OutputFile, OutputJSON, "data", (std::uint8_t *)infobuffer, infobuffersize2);
			}

			DumpOutput(OutputFile, OutputJSON);

			OutputJSON.EndObject();
		}
	}

	if (infobuffer != NULL)  ::LocalFree(infobuffer);
}

// This is a little bit of a hacky workaround since the code is ultimately intended to be used within createprocess.
const char *GxErrorStr = NULL, *GxErrorCode = NULL;
DWORD GxWinError = 0;
void DumpErrorMsg(const char *errorstr, const char *errorcode, DWORD winerror)
{
	GxErrorStr = errorstr;
	GxErrorCode = errorcode;
	GxWinError = winerror;
}

void DumpWideErrorMsg(const WCHAR *errorstr, const char *errorcode, DWORD winerror)
{
	char *errorstr2;
	BOOL useddefaultchar = FALSE;
	int retval = ::WideCharToMultiByte(CP_ACP, 0, errorstr, -1, NULL, 0, NULL, &useddefaultchar);
	if (!retval)
	{
		DumpErrorMsg("Unable to convert error message to multibyte.", "wide_char_to_multibyte_failed", ::GetLastError());

		return;
	}

	DWORD tempsize = (DWORD)retval;
	errorstr2 = (char *)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, tempsize);
	if (errorstr2 == NULL)
	{
		DumpErrorMsg("Error message buffer allocation failed.", "heap_alloc_failed", ::GetLastError());

		return;
	}

	useddefaultchar = FALSE;
	retval = ::WideCharToMultiByte(CP_ACP, 0, errorstr, -1, errorstr2, tempsize, NULL, &useddefaultchar);
	if (!retval)
	{
		DumpErrorMsg("Unable to convert error message to multibyte.", "wide_char_to_multibyte_failed", ::GetLastError());

		::HeapFree(::GetProcessHeap(), 0, errorstr2);

		return;
	}

	size_t y = strlen(errorstr2);
	while (y && (errorstr2[y - 1] == '\r' || errorstr2[y - 1] == '\n'))  errorstr2[--y] = '\0';

	// Display the error message.
	DumpErrorMsg(errorstr2, errorcode, winerror);

// Intentionally leaking the error message string.
//	::HeapFree(::GetProcessHeap(), 0, errorstr2);
}

inline void FreeTokenInformation(LPVOID tinfo)
{
	if (tinfo != NULL)  ::HeapFree(::GetProcessHeap(), 0, tinfo);
}

LPVOID AllocateAndGetTokenInformation(HANDLE token, TOKEN_INFORMATION_CLASS infoclass, DWORD sizehint)
{
	LPVOID tinfo;
	DWORD tinfosize = sizehint;
	bool success;

	tinfo = (LPVOID)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, tinfosize);
	if (tinfo == NULL)  tinfosize = 0;

	// Resize until the buffer is big enough.
	while (!(success = ::GetTokenInformation(token, infoclass, tinfo, tinfosize, &tinfosize)) && ::GetLastError() == ERROR_INSUFFICIENT_BUFFER)
	{
		if (tinfo != NULL)  FreeTokenInformation(tinfo);

		tinfo = (LPVOID)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, tinfosize);
		if (tinfo == NULL)
		{
			tinfosize = 0;

			break;
		}
	}

	return tinfo;
}

// Get/Duplicate the primary token of the specified process ID as a primary or impersonation token.
// duptype is ignored if accessmode does not specify TOKEN_DUPLICATE.
HANDLE GetTokenFromPID(DWORD pid, TOKEN_TYPE duptype, DWORD accessmode = TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY)
{
	HANDLE tempproc;
	HANDLE tokenhandle, tokenhandle2;

	// Enable SeDebugPrivilege.
	SetThreadProcessPrivilege(L"SeDebugPrivilege", true);

	// Open a handle to the process.
	tempproc = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	if (tempproc == NULL)  tempproc = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

	if (tempproc == NULL)
	{
		DumpErrorMsg("Unable to open a handle to the specified process.", "open_process_failed", ::GetLastError());

		return INVALID_HANDLE_VALUE;
	}

	if (!::OpenProcessToken(tempproc, accessmode, &tokenhandle) && (!(accessmode & TOKEN_QUERY_SOURCE) || !::OpenProcessToken(tempproc, accessmode & ~TOKEN_QUERY_SOURCE, &tokenhandle)))
	{
		DumpErrorMsg("Unable to open a handle to the specified process token.", "open_process_token_failed", ::GetLastError());

		::CloseHandle(tempproc);

		return INVALID_HANDLE_VALUE;
	}

	::CloseHandle(tempproc);

	if (!(accessmode & TOKEN_DUPLICATE))  tokenhandle2 = tokenhandle;
	else
	{
		SECURITY_ATTRIBUTES secattr = {0};
		secattr.nLength = sizeof(secattr);
		secattr.bInheritHandle = FALSE;
		secattr.lpSecurityDescriptor = NULL;

		if (!::DuplicateTokenEx(tokenhandle, MAXIMUM_ALLOWED, &secattr, SecurityImpersonation, duptype, &tokenhandle2))
		{
			DumpErrorMsg("Unable to duplicate the specified process token.", "duplicate_token_ex_failed", ::GetLastError());

			::CloseHandle(tokenhandle);

			return INVALID_HANDLE_VALUE;
		}

		::CloseHandle(tokenhandle);
	}

	return tokenhandle2;
}

void GetNumSIDsAndLUIDs(LPWSTR tokenopts, size_t &numsids, size_t &numluids)
{
	size_t x = 0;

	numsids = 0;
	numluids = 0;
	while (tokenopts[x] && tokenopts[x] != L';')
	{
		for (; tokenopts[x] && tokenopts[x] != L';' && tokenopts[x] != L'S'; x++);

		if (tokenopts[x] == L'S')
		{
			if (tokenopts[x + 1] == L'-')  numsids++;
			else if (tokenopts[x + 1] == L'e')  numluids++;
		}

		for (; tokenopts[x] && tokenopts[x] != L';' && tokenopts[x] != L','; x++);

		if (tokenopts[x] == L',')  x++;
	}
}

bool GetNextTokenOptsSID(LPWSTR tokenopts, size_t &x, PSID &sidbuffer)
{
	size_t x2;
	WCHAR tempchr;

	for (x2 = x; tokenopts[x2] && tokenopts[x2] != L';' && tokenopts[x2] != L':' && tokenopts[x2] != L','; x2++);
	tempchr = tokenopts[x2];
	tokenopts[x2] = L'\0';

	bool result = ::ConvertStringSidToSidW(tokenopts + x, &sidbuffer);
	if (!result)
	{
		DWORD winerror = ::GetLastError();
		CubicleSoft::StaticWCMixedVar<WCHAR[8192]> TempVar;

		TempVar.SetFormattedStr(L"The specified SID '%ls' in the token options is invalid.", tokenopts + x);

		DumpWideErrorMsg(TempVar.GetStr(), "invalid_sid", winerror);
	}

	tokenopts[x2] = tempchr;
	x = x2;

	return result;
}

bool GetNextTokenOptsLUID(LPWSTR tokenopts, size_t &x, LUID &luidbuffer)
{
	size_t x2;
	WCHAR tempchr;

	for (x2 = x; tokenopts[x2] && tokenopts[x2] != L';' && tokenopts[x2] != L':' && tokenopts[x2] != L','; x2++);
	tempchr = tokenopts[x2];
	tokenopts[x2] = L'\0';

	bool result = ::LookupPrivilegeValueW(NULL, tokenopts + x, &luidbuffer);
	if (!result)
	{
		DWORD winerror = ::GetLastError();
		CubicleSoft::StaticWCMixedVar<WCHAR[8192]> TempVar;

		TempVar.SetFormattedStr(L"The specified privilege '%ls' in the token options is invalid.", tokenopts + x);

		DumpWideErrorMsg(TempVar.GetStr(), "invalid_privilege", winerror);
	}

	tokenopts[x2] = tempchr;
	x = x2;

	return result;
}

DWORD GetNextTokenOptsAttrs(LPWSTR tokenopts, size_t &x)
{
	size_t x2;
	WCHAR tempchr;

	if (tokenopts[x] != L':')  return 0;
	x++;

	for (x2 = x; tokenopts[x2] && tokenopts[x2] != L';' && tokenopts[x2] != L','; x2++);
	tempchr = tokenopts[x2];
	tokenopts[x2] = L'\0';

	DWORD result = (DWORD)_wtoi(tokenopts + x);

	tokenopts[x2] = tempchr;
	x = x2;

	return result;
}

// Attempts to locate an existing token that matches the input option string.
// duptype is ignored if accessmode does not specify TOKEN_DUPLICATE.
// Example:  FindExistingTokenFromOpts(L"S-1-16-16384,SeDebugPrivilege,SeAssignPrimaryTokenPrivilege", true)
HANDLE FindExistingTokenFromOpts(LPWSTR tokenopts, TOKEN_TYPE duptype, DWORD accessmode = TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY)
{
	if (tokenopts[0] != L'S')  return GetTokenFromPID(_wtoi(tokenopts), duptype, accessmode);

	// Split and convert the options into SIDs and privilege LUIDs.
	CubicleSoft::StaticWCMixedVar<WCHAR[8192]> TempVar;
	size_t x, x2, numsids, numluids;
	PSID *sids = NULL;
	LUID *luids = NULL;

	TempVar.SetStr(tokenopts);
	WCHAR *tokenopts2 = TempVar.GetStr();

	GetNumSIDsAndLUIDs(tokenopts2, numsids, numluids);

	if (numsids)  sids = (PSID *)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, numsids * sizeof(PSID));
	if (numluids)  luids = (LUID *)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, numluids * sizeof(LUID));

	bool valid = true;
	x = 0;
	numsids = 0;
	numluids = 0;
	while (tokenopts2[x])
	{
		for (; tokenopts2[x] && tokenopts2[x] != L'S'; x++);

		if (tokenopts2[x] == L'S')
		{
			if (tokenopts2[x + 1] == L'-')
			{
				valid = GetNextTokenOptsSID(tokenopts2, x, sids[numsids]);
				if (!valid)  break;

				numsids++;
			}
			else if (tokenopts2[x + 1] == L'e')
			{
				valid = GetNextTokenOptsLUID(tokenopts2, x, luids[numluids]);
				if (!valid)  break;

				numluids++;
			}
		}

		for (; tokenopts2[x] && tokenopts2[x] != L','; x++);

		if (tokenopts2[x] == L',')  x++;
	}

	// Find a process that has matching SIDs and LUIDs.
	HANDLE result = INVALID_HANDLE_VALUE;
	if (valid)
	{
		// Enable SeDebugPrivilege.
		SetThreadProcessPrivilege(L"SeDebugPrivilege", true);

		// Get the list of currently running processes.
		HANDLE snaphandle, tempproc, proctoken, duptoken;
		PTOKEN_USER user = NULL;
		PTOKEN_GROUPS groups = NULL;
		PTOKEN_PRIVILEGES privs = NULL;
		BOOL result2;

		snaphandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snaphandle == INVALID_HANDLE_VALUE)  DumpErrorMsg("Unable to retrieve the list of running processes.", "create_toolhelp32_snapshot_failed", ::GetLastError());
		else
		{
			PROCESSENTRY32 pe32;
			pe32.dwSize = sizeof(PROCESSENTRY32);

			if (::Process32First(snaphandle, &pe32))
			{
				do
				{
					// Open a handle to the process.
					tempproc = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe32.th32ProcessID);
					if (tempproc == NULL)  tempproc = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);

					if (tempproc != NULL)
					{
						result2 = ::OpenProcessToken(tempproc, accessmode, &proctoken);
						if (result2 == NULL && (accessmode & TOKEN_QUERY_SOURCE))  result2 = ::OpenProcessToken(tempproc, accessmode & ~TOKEN_QUERY_SOURCE, &proctoken);
//						DWORD pid = ::GetProcessId(tempproc);

						::CloseHandle(tempproc);

						if (result2)
						{
							// Load token user, groups, and privileges.
							user = (PTOKEN_USER)AllocateAndGetTokenInformation(proctoken, TokenUser, 4096);
							groups = (PTOKEN_GROUPS)AllocateAndGetTokenInformation(proctoken, TokenGroups, 4096);
							privs = (PTOKEN_PRIVILEGES)AllocateAndGetTokenInformation(proctoken, TokenPrivileges, 4096);

							if (user != NULL && groups != NULL && privs != NULL)
							{
								// Match SIDs.
								for (x = 0; x < numsids; x++)
								{
									if (!::EqualSid(user->User.Sid, sids[x]))
									{
										for (x2 = 0; x2 < groups->GroupCount && !::EqualSid(groups->Groups[x2].Sid, sids[x]); x2++);

										if (x2 >= groups->GroupCount)  break;
									}
								}

								if (x >= numsids)
								{
									// Match privileges.
									for (x = 0; x < numluids; x++)
									{
										for (x2 = 0; x2 < privs->PrivilegeCount && (privs->Privileges[x2].Luid.LowPart != luids[x].LowPart || privs->Privileges[x2].Luid.HighPart != luids[x].HighPart); x2++);

										if (x2 >= privs->PrivilegeCount)  break;
									}

									if (x >= numluids)
									{
										// Everything matches.  Duplicate the token.
										if (accessmode & TOKEN_DUPLICATE)
										{
											SECURITY_ATTRIBUTES secattr = {0};
											secattr.nLength = sizeof(secattr);
											secattr.bInheritHandle = FALSE;
											secattr.lpSecurityDescriptor = NULL;

											if (::DuplicateTokenEx(proctoken, MAXIMUM_ALLOWED, &secattr, SecurityImpersonation, duptype, &duptoken))
											{
												result = duptoken;
											}
										}
										else
										{
											result = proctoken;
											proctoken = NULL;
										}
									}
								}
							}

							FreeTokenInformation((LPVOID)privs);
							FreeTokenInformation((LPVOID)groups);
							FreeTokenInformation((LPVOID)user);

							if (proctoken != NULL)  ::CloseHandle(proctoken);
						}
					}
				} while (result == INVALID_HANDLE_VALUE && ::Process32Next(snaphandle, &pe32));
			}

			::CloseHandle(snaphandle);

			if (result == INVALID_HANDLE_VALUE)  DumpErrorMsg("Unable to find a matching process for the token options.", "no_match_found", ::GetLastError());
		}
	}

	for (x = 0; x < numsids; x++)  ::FreeSid(sids[x]);

	::HeapFree(::GetProcessHeap(), 0, (LPVOID)sids);
	::HeapFree(::GetProcessHeap(), 0, (LPVOID)luids);

	return result;
}

CubicleSoft::SharedLib::ModuleUtil GxNTDLL("ntdll.dll");
CubicleSoft::SharedLib::FunctionUtil GxNtCreateToken(GxNTDLL, "NtCreateToken");
CubicleSoft::SharedLib::FunctionUtil GxRtlNtStatusToDosError(GxNTDLL, "RtlNtStatusToDosError");

// Attempts to create a new token based on the input string.
HANDLE CreateTokenFromOpts(LPWSTR tokenopts, bool primary, HANDLE wildcardprocesshandle = ::GetCurrentProcess(), DWORD desiredaccess = TOKEN_ALL_ACCESS)
{
	// Enable or obtain and then enable SeCreateTokenPrivilege.
	if (!SetThreadProcessPrivilege(L"SeCreateTokenPrivilege", true))
	{
		// Obtain an impersonation token containing the privilege.
		HANDLE tokenhandle = FindExistingTokenFromOpts((LPWSTR)L"SeCreateTokenPrivilege", TokenImpersonation);

		if (tokenhandle == INVALID_HANDLE_VALUE)  return INVALID_HANDLE_VALUE;

		// Assign the impersonation token to the current thread.
		if (!::SetThreadToken(NULL, tokenhandle))
		{
			DumpErrorMsg("Unable to assign the token to the thread.", "set_thread_token_failed", ::GetLastError());

			return INVALID_HANDLE_VALUE;
		}

		// Enable the privilege.
		if (!SetThreadProcessPrivilege(L"SeCreateTokenPrivilege", true))
		{
			DumpErrorMsg("Unable to enable SeCreateTokenPrivilege.", "enable_privilege_failed", ::GetLastError());

			return INVALID_HANDLE_VALUE;
		}
	}

	// Split and convert the options.
	CubicleSoft::StaticWCMixedVar<WCHAR[8192]> TempVar;
	WCHAR tempchr;
	size_t x, x2, numsids, numluids;
	bool valid = true, freeusersid = false, freegroupsids = false, freeownersid = false, freeprimarygroupsid = false;
	HANDLE currtoken, result = INVALID_HANDLE_VALUE;
	PTOKEN_USER user = NULL;
	PTOKEN_GROUPS groups = NULL;
	PTOKEN_PRIVILEGES privs = NULL;
	PTOKEN_OWNER owner = NULL;
	PTOKEN_PRIMARY_GROUP primarygroup = NULL;
	PSECURITY_DESCRIPTOR sd = NULL;
	PTOKEN_DEFAULT_DACL defaultdacl = NULL;
	PTOKEN_SOURCE source = NULL;

	TempVar.SetStr(tokenopts);
	WCHAR *tokenopts2 = TempVar.GetStr();

	// For wildcard options (*), use the specified process token.
	if (!::OpenProcessToken(wildcardprocesshandle, TOKEN_QUERY | TOKEN_QUERY_SOURCE, &currtoken) && !::OpenProcessToken(wildcardprocesshandle, TOKEN_QUERY, &currtoken))
	{
		DumpErrorMsg("Unable to obtain a handle to the process token.", "open_process_token_failed", ::GetLastError());

		return INVALID_HANDLE_VALUE;
	}

	// Get the user SID.
	x = 0;
	for (; tokenopts2[x] && tokenopts2[x] == L' '; x++);

	if (tokenopts2[x] == L'*')
	{
		user = (PTOKEN_USER)AllocateAndGetTokenInformation(currtoken, TokenUser, 4096);
		if (user == NULL)
		{
			DumpErrorMsg("Unable to retrieve user for the current token.", "allocate_and_get_token_info_failed", ::GetLastError());

			valid = false;
		}
	}
	else
	{
		user = (PTOKEN_USER)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TOKEN_USER));
		if (user != NULL)
		{
			valid = GetNextTokenOptsSID(tokenopts2, x, user->User.Sid);
			if (valid)  freeusersid = true;

			// Attributes are always ignored for the user and must be 0.
			user->User.Attributes = 0;
		}
	}

	for (; tokenopts2[x] && tokenopts2[x] != L';'; x++);
	if (tokenopts2[x] == L';')  x++;

	// Get group SIDs and attributes.
	if (valid)
	{
		for (; tokenopts2[x] && tokenopts2[x] == L' '; x++);

		if (tokenopts2[x] == L'*')
		{
			groups = (PTOKEN_GROUPS)AllocateAndGetTokenInformation(currtoken, TokenGroups, 4096);
			if (groups == NULL)
			{
				DumpErrorMsg("Unable to retrieve group SIDs and attributes for the current token.", "allocate_and_get_token_info_failed", ::GetLastError());

				valid = false;
			}
		}
		else
		{
			GetNumSIDsAndLUIDs(tokenopts2 + x, numsids, numluids);

			groups = (PTOKEN_GROUPS)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TOKEN_GROUPS) + sizeof(SID_AND_ATTRIBUTES) * numsids);
			if (groups != NULL)
			{
				freegroupsids = true;

				groups->GroupCount = (DWORD)numsids;

				for (x2 = 0; valid && x2 < numsids; x2++)
				{
					valid = GetNextTokenOptsSID(tokenopts2, x, groups->Groups[x2].Sid);

					groups->Groups[x2].Attributes = GetNextTokenOptsAttrs(tokenopts2, x);

					if (tokenopts2[x] == L',')  x++;
				}

				if (!valid)  numsids = x2;
			}
		}

		for (; tokenopts2[x] && tokenopts2[x] != L';'; x++);
		if (tokenopts2[x] == L';')  x++;
	}

	// Get privileges and attributes.
	if (valid)
	{
		for (; tokenopts2[x] && tokenopts2[x] == L' '; x++);

		if (tokenopts2[x] == L'*')
		{
			privs = (PTOKEN_PRIVILEGES)AllocateAndGetTokenInformation(currtoken, TokenPrivileges, 4096);
			if (privs == NULL)
			{
				DumpErrorMsg("Unable to retrieve privileges and attributes for the current token.", "allocate_and_get_token_info_failed", ::GetLastError());

				valid = false;
			}
		}
		else
		{
			GetNumSIDsAndLUIDs(tokenopts2 + x, numsids, numluids);

			privs = (PTOKEN_PRIVILEGES)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TOKEN_PRIVILEGES) + sizeof(LUID_AND_ATTRIBUTES) * numluids);
			if (privs != NULL)
			{
				privs->PrivilegeCount = (DWORD)numluids;

				for (x2 = 0; valid && x2 < numluids; x2++)
				{
					valid = GetNextTokenOptsLUID(tokenopts2, x, privs->Privileges[x2].Luid);

					privs->Privileges[x2].Attributes = GetNextTokenOptsAttrs(tokenopts2, x);

					if (tokenopts2[x] == L',')  x++;
				}

				if (!valid)  numluids = x2;
			}
		}

		for (; tokenopts2[x] && tokenopts2[x] != L';'; x++);
		if (tokenopts2[x] == L';')  x++;
	}

	// Get the owner SID.
	if (valid)
	{
		for (; tokenopts2[x] && tokenopts2[x] == L' '; x++);

		if (tokenopts2[x] == L'*')
		{
			owner = (PTOKEN_OWNER)AllocateAndGetTokenInformation(currtoken, TokenOwner, 4096);
			if (owner == NULL)
			{
				DumpErrorMsg("Unable to retrieve the owner for the current token.", "allocate_and_get_token_info_failed", ::GetLastError());

				valid = false;
			}
		}
		else
		{
			owner = (PTOKEN_OWNER)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TOKEN_OWNER));
			if (owner != NULL)
			{
				valid = GetNextTokenOptsSID(tokenopts2, x, owner->Owner);
				if (valid)  freeownersid = true;
			}
		}

		for (; tokenopts2[x] && tokenopts2[x] != L';'; x++);
		if (tokenopts2[x] == L';')  x++;
	}

	// Get the primary group SID.
	if (valid)
	{
		for (; tokenopts2[x] && tokenopts2[x] == L' '; x++);

		if (tokenopts2[x] == L'*')
		{
			primarygroup = (PTOKEN_PRIMARY_GROUP)AllocateAndGetTokenInformation(currtoken, TokenPrimaryGroup, 4096);
			if (primarygroup == NULL)
			{
				DumpErrorMsg("Unable to retrieve the primary group for the current token.", "allocate_and_get_token_info_failed", ::GetLastError());

				valid = false;
			}
		}
		else
		{
			primarygroup = (PTOKEN_PRIMARY_GROUP)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TOKEN_PRIMARY_GROUP));
			if (primarygroup != NULL)
			{
				valid = GetNextTokenOptsSID(tokenopts2, x, primarygroup->PrimaryGroup);
				if (valid)  freeprimarygroupsid = true;
			}
		}

		for (; tokenopts2[x] && tokenopts2[x] != L';'; x++);
		if (tokenopts2[x] == L';')  x++;
	}

	// Get the default DACL.
	if (valid)
	{
		for (; tokenopts2[x] && tokenopts2[x] == L' '; x++);

		if (tokenopts2[x] == L'*')
		{
			defaultdacl = (PTOKEN_DEFAULT_DACL)AllocateAndGetTokenInformation(currtoken, TokenDefaultDacl, 4096);
			if (defaultdacl == NULL)
			{
				DumpErrorMsg("Unable to retrieve the default DACL for the current token.", "allocate_and_get_token_info_failed", ::GetLastError());

				valid = false;
			}
		}
		else
		{
			for (x2 = x; tokenopts2[x2] && tokenopts2[x2] != L';'; x2++)
			{
				if (tokenopts2[x2] == L'(')
				{
					for (; tokenopts2[x2] && tokenopts2[x2] != L')'; x2++);
				}
			}
			tempchr = tokenopts2[x2];
			tokenopts2[x2] = L'\0';

			defaultdacl = (PTOKEN_DEFAULT_DACL)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TOKEN_DEFAULT_DACL));
			if (defaultdacl != NULL)
			{
				BOOL daclpresent, dacldefaulted;

				valid = ::ConvertStringSecurityDescriptorToSecurityDescriptorW(tokenopts2 + x, SDDL_REVISION_1, &sd, NULL) && ::GetSecurityDescriptorDacl(sd, &daclpresent, &defaultdacl->DefaultDacl, &dacldefaulted) && daclpresent;
				if (!valid)  DumpErrorMsg("The specified default DACL in the token options is invalid.", "invalid_default_dacl", ::GetLastError());
			}

			tokenopts2[x2] = tempchr;
			x = x2;
		}

		for (; tokenopts2[x] && tokenopts2[x] != L';'; x++);
		if (tokenopts2[x] == L';')  x++;
	}

	// Get the source and source LUID.
	if (valid)
	{
		for (; tokenopts2[x] && tokenopts2[x] == L' '; x++);

		if (tokenopts2[x] == L'*')
		{
			source = (PTOKEN_SOURCE)AllocateAndGetTokenInformation(currtoken, TokenSource, sizeof(TOKEN_SOURCE));
			if (source == NULL)
			{
				DumpErrorMsg("Unable to retrieve the source for the current token.", "allocate_and_get_token_info_failed", ::GetLastError());

				valid = false;
			}
		}
		else
		{
			for (x2 = x; tokenopts2[x2] && x2 - x != TOKEN_SOURCE_LENGTH * 2; x2++);

			if (tokenopts2[x2] != L':')  DumpErrorMsg("The specified source in the token options is invalid.", "invalid_source", ::GetLastError());
			else
			{
				source = (PTOKEN_SOURCE)::HeapAlloc(::GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TOKEN_SOURCE));

				// Convert from hex.
				for (x2 = x; tokenopts2[x2] && x2 - x != TOKEN_SOURCE_LENGTH * 2; x2 += 2)
				{
					if (tokenopts2[x2] >= L'0' && tokenopts2[x2] <= L'9')  tempchr = tokenopts2[x2] - L'0';
					else if (tokenopts2[x2] >= L'A' && tokenopts2[x2] <= L'F')  tempchr = tokenopts2[x2] - L'A';
					else if (tokenopts2[x2] >= L'a' && tokenopts2[x2] <= L'f')  tempchr = tokenopts2[x2] - L'a';
					else  tempchr = 0;

					tempchr <<= 4;

					if (tokenopts2[x2 + 1] >= L'0' && tokenopts2[x2 + 1] <= L'9')  tempchr |= tokenopts2[x2 + 1] - L'0';
					else if (tokenopts2[x2 + 1] >= L'A' && tokenopts2[x2 + 1] <= L'F')  tempchr |= tokenopts2[x2 + 1] - L'A';
					else if (tokenopts2[x2 + 1] >= L'a' && tokenopts2[x2 + 1] <= L'f')  tempchr |= tokenopts2[x2 + 1] - L'a';

					source->SourceName[(x2 - x) / 2] = (CHAR)tempchr;
				}

				std::uint64_t tempid = _wtoi64(tokenopts2 + x2 + 1);

				source->SourceIdentifier.HighPart = tempid >> 32;
				source->SourceIdentifier.LowPart = tempid & 0xFFFFFFFF;
			}
		}
	}

	// Create the token.
	if (valid && user != NULL && groups != NULL && privs != NULL && owner != NULL && primarygroup != NULL && defaultdacl != NULL && source != NULL)
	{
		NTSTATUS status;
		HANDLE temphandle;
		TOKEN_STATISTICS tokenstats;
		DWORD templen;
		DWORD winerror;

		if (!::GetTokenInformation(currtoken, TokenStatistics, &tokenstats, sizeof(tokenstats), &templen))  DumpErrorMsg("Unable to get statistics for the current token.", "get_token_info_failed", ::GetLastError());
		else
		{
			SECURITY_QUALITY_OF_SERVICE tempsqos = {
				sizeof(tempsqos), SecurityImpersonation, SECURITY_DYNAMIC_TRACKING
			};

			OBJECT_ATTRIBUTES tempoa = {
				sizeof(tempoa), 0, 0, 0, 0, &tempsqos
			};

			if (CubicleSoft::SharedLib::Stdcall<NTSTATUS, PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, TOKEN_TYPE, PLUID, PLARGE_INTEGER, PTOKEN_USER, PTOKEN_GROUPS, PTOKEN_PRIVILEGES, PTOKEN_OWNER, PTOKEN_PRIMARY_GROUP, PTOKEN_DEFAULT_DACL, PTOKEN_SOURCE>(GxNtCreateToken, status, &temphandle, desiredaccess, &tempoa, (primary ? TokenPrimary : TokenImpersonation), &tokenstats.AuthenticationId, &tokenstats.ExpirationTime, user, groups, privs, owner, primarygroup, defaultdacl, source) && status >= 0)
			{
				result = temphandle;
			}
			else
			{
				if (CubicleSoft::SharedLib::Stdcall<ULONG, NTSTATUS>(GxRtlNtStatusToDosError, winerror, status) && winerror != ERROR_MR_MID_NOT_FOUND)  DumpErrorMsg("Failed to create a token.", "nt_create_token_failed", winerror);
				else  DumpErrorMsg("Failed to create a token and failed to retrieve a Windows error code mapping.", "nt_create_token_failed", status);
			}
		}
	}

	::CloseHandle(currtoken);

	// Cleanup.
	if (user != NULL)
	{
		if (freeusersid)  ::FreeSid(user->User.Sid);

		FreeTokenInformation((LPVOID)user);
	}

	if (groups != NULL)
	{
		for (x = 0; x < numsids; x++)  ::FreeSid(groups->Groups[x].Sid);

		FreeTokenInformation((LPVOID)groups);
	}

	if (privs != NULL)  FreeTokenInformation((LPVOID)privs);

	if (owner != NULL)
	{
		if (freeownersid)  ::FreeSid(owner->Owner);

		FreeTokenInformation((LPVOID)owner);
	}

	if (primarygroup != NULL)
	{
		if (freeprimarygroupsid)  ::FreeSid(primarygroup->PrimaryGroup);

		FreeTokenInformation((LPVOID)primarygroup);
	}

	if (sd != NULL)  ::LocalFree(sd);
	if (defaultdacl != NULL)  FreeTokenInformation((LPVOID)defaultdacl);
	if (source != NULL)  FreeTokenInformation((LPVOID)source);

	return result;
}


int _tmain(int argc, TCHAR **argv)
{
	bool verbose = false;
	HANDLE createtokenwildhandle = ::GetCurrentProcess();
	HANDLE procthreadhandle = INVALID_HANDLE_VALUE;
	HANDLE tokenhandle = INVALID_HANDLE_VALUE;
	LPTSTR filename = NULL;
	bool classes[GxNumTokenClasses] = { false };
	bool classesused = false, rawdata = false;
	int result = 0;
	const char *errorstr = NULL, *errorcode = NULL;
	DWORD winerror;

	CubicleSoft::UTF8::UTF8MixedVar<char[8192]> TempVar;

	// Process command-line options.
	int x;
	for (x = 1; x < argc; x++)
	{
		if (!_tcsicmp(argv[x], _T("/v")))  verbose = true;
		else if (!_tcsicmp(argv[x], _T("/?")) || !_tcsicmp(argv[x], _T("/h")))
		{
			DumpSyntax(argv[0]);

			return 1;
		}
		else if (!_tcsicmp(argv[x], _T("/login")))
		{
			if (procthreadhandle == INVALID_HANDLE_VALUE)
			{
				NTSTATUS ntstatus, ntstatus2;
				HANDLE lsahandle;

				if ((ntstatus = ::LsaConnectUntrusted(&lsahandle)) != ERROR_SUCCESS)
				{
					errorstr = "Unable to obtained untrusted LSA handle.";
					errorcode = "lsa_connect_untrusted_failed";
					winerror = ::LsaNtStatusToWinError(ntstatus);
				}
				else
				{
					// Get credentials from the user.
					CREDUI_INFO cuiinfo;

					cuiinfo.cbSize = sizeof(cuiinfo);
					cuiinfo.hwndParent = ::GetConsoleWindow();
					cuiinfo.pszMessageText = _T("Enter a login to get the token information for.");
					cuiinfo.pszCaptionText = _T("GetTokenInformation Login");
					cuiinfo.hbmBanner = NULL;

					ULONG authpackage = 0;
					LPVOID credbuffer = NULL;
					ULONG credbuffersize = 0;
					if ((ntstatus = ::CredUIPromptForWindowsCredentials(&cuiinfo, 0, &authpackage, NULL, 0, &credbuffer, &credbuffersize, NULL, 0)) != ERROR_SUCCESS)
					{
						if (ntstatus == ERROR_CANCELLED)
						{
							errorstr = "The Windows credentials dialog was cancelled.";
							errorcode = "credentials_dialog_cancelled";
							winerror = ntstatus;
						}
						else
						{
							errorstr = "The request to prompt for credentials failed.";
							errorcode = "cred_ui_prompt_for_windows_credentials_failed";
							winerror = ::LsaNtStatusToWinError(ntstatus);
						}
					}
					else
					{
						// Get a token handle from the credentials.
						LSA_STRING origin;
						TOKEN_SOURCE source = { { "User32 " }, {0, 0} };
						void *profilebuffer = NULL;
						ULONG profilebuffersize = 0;
						QUOTA_LIMITS quotalimits;
						LUID templuid;

						origin.Buffer = (PCHAR)"gettokeninformation";
						origin.Length = (USHORT)strlen(origin.Buffer);
						origin.MaximumLength = origin.Length + 1;

						if ((ntstatus = ::LsaLogonUser(lsahandle, &origin, Interactive, authpackage, credbuffer, credbuffersize, NULL, &source, &profilebuffer, &profilebuffersize, &templuid, &tokenhandle, &quotalimits, &ntstatus2)) != ERROR_SUCCESS)
						{
							if (ntstatus == STATUS_ACCOUNT_RESTRICTION)
							{
								errorstr = "The login failed due to an account restriction.";
								errorcode = "lsa_logon_user_failed";
								winerror = ::LsaNtStatusToWinError(ntstatus2);
							}
							else
							{
								errorstr = "The login failed.";
								errorcode = "lsa_logon_user_failed";
								winerror = ::LsaNtStatusToWinError(ntstatus);
							}
						}

						if (profilebuffer != NULL)  ::LsaFreeReturnBuffer(profilebuffer);

						::SecureZeroMemory(credbuffer, credbuffersize);
						::CoTaskMemFree(credbuffer);
					}

					::LsaDeregisterLogonProcess(lsahandle);
				}

				procthreadhandle = NULL;
			}
		}
		else if (!_tcsncicmp(argv[x], _T("/pid="), 5))
		{
			if (procthreadhandle == INVALID_HANDLE_VALUE)
			{
				DWORD pid = (DWORD)_tstoi(argv[x] + 5);

				procthreadhandle = NULL;

				tokenhandle = GetTokenFromPID(pid, TokenPrimary, TOKEN_QUERY | TOKEN_QUERY_SOURCE);
				if (tokenhandle == INVALID_HANDLE_VALUE)
				{
					errorstr = GxErrorStr;
					errorcode = GxErrorCode;
					winerror = GxWinError;
				}
			}
		}
		else if (!_tcsncicmp(argv[x], _T("/tid="), 5))
		{
			if (procthreadhandle == INVALID_HANDLE_VALUE)
			{
				DWORD tid = (DWORD)_tstoi(argv[x] + 5);

				// Attempt to enable SeDebugPrivilege.
				SetThreadProcessPrivilege(L"SeDebugPrivilege", true);

				procthreadhandle = ::OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
				if (procthreadhandle == NULL)  procthreadhandle = ::OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);

				if (procthreadhandle == NULL)
				{
					errorstr = "Unable to open a handle to the specified thread.";
					errorcode = "open_thread_failed";
					winerror = ::GetLastError();
				}
				else if (!::OpenThreadToken(procthreadhandle, TOKEN_QUERY | TOKEN_QUERY_SOURCE, FALSE, &tokenhandle) && !::OpenThreadToken(procthreadhandle, TOKEN_QUERY | TOKEN_QUERY_SOURCE, TRUE, &tokenhandle) && !::OpenThreadToken(procthreadhandle, TOKEN_QUERY, FALSE, &tokenhandle) && !::OpenThreadToken(procthreadhandle, TOKEN_QUERY, TRUE, &tokenhandle))
				{
					errorstr = "Unable to open a handle to the thread token.";
					errorcode = "open_thread_token_failed";
					winerror = ::GetLastError();
				}
			}
		}
		else if (!_tcsncicmp(argv[x], _T("/usetoken="), 10))
		{
			if (procthreadhandle == INVALID_HANDLE_VALUE)
			{
				procthreadhandle = NULL;

				tokenhandle = FindExistingTokenFromOpts(argv[x] + 10, TokenPrimary, TOKEN_QUERY | TOKEN_QUERY_SOURCE);
				if (tokenhandle == INVALID_HANDLE_VALUE)
				{
					errorstr = GxErrorStr;
					errorcode = GxErrorCode;
					winerror = GxWinError;
				}
			}
		}
		else if (!_tcsncicmp(argv[x], _T("/createtokenwild="), 17))
		{
			DWORD pid = (DWORD)_tstoi(argv[x] + 17);

			// Enable SeDebugPrivilege.
			SetThreadProcessPrivilege(L"SeDebugPrivilege", true);

			// Open a handle to the process.
			HANDLE tempproc = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
			if (tempproc == NULL)  tempproc = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

			if (tempproc == NULL)
			{
				errorstr = "Unable to open a handle to the specified /createtokenwildcard process.";
				errorcode = "open_process_failed";
				winerror = ::GetLastError();
			}
			else
			{
				::CloseHandle(createtokenwildhandle);

				createtokenwildhandle = tempproc;
			}
		}
		else if (!_tcsncicmp(argv[x], _T("/createtoken="), 13))
		{
			if (procthreadhandle == INVALID_HANDLE_VALUE)
			{
				procthreadhandle = NULL;

				tokenhandle = CreateTokenFromOpts(argv[x] + 13, true, createtokenwildhandle);
				if (tokenhandle == INVALID_HANDLE_VALUE)
				{
					errorstr = GxErrorStr;
					errorcode = GxErrorCode;
					winerror = GxWinError;
				}
			}
		}
		else if (!_tcsicmp(argv[x], _T("/raw")))  rawdata = true;
		else if (!_tcsncicmp(argv[x], _T("/file="), 6))  filename = argv[x] + 6;
		else if (!_tcsncicmp(argv[x], _T("/c="), 3))
		{
			size_t x2;

			TempVar.SetUTF8(argv[x] + 3);

			for (x2 = 1; x2 < GxNumTokenClasses && stricmp(TempVar.GetStr(), GxTokenClasses[x2]); x2++)  {}

			if (x2 < GxNumTokenClasses)
			{
				classes[x2] = true;

				classesused = true;
			}
		}
		else if (!_tcsicmp(argv[x], _T("/attach")))
		{
#ifdef SUBSYSTEM_WINDOWS
			// For the Windows subsystem only, attempt to attach to a parent console if it exists.
			InitVerboseMode();
#endif
		}
		else
		{
			// Probably reached the command to execute portion of the arguments.
			break;
		}
	}

	if (verbose)
	{
#ifdef SUBSYSTEM_WINDOWS
		InitVerboseMode();
#endif

		_tprintf(_T("Arguments:\n"));
		for (int x2 = 0; x2 < argc; x2++)
		{
			_tprintf(_T("\targv[%d] = %s\n"), x2, argv[x2]);
		}
		_tprintf(_T("\n"));
	}

	// Open a handle to the current process.
	if (procthreadhandle == INVALID_HANDLE_VALUE)
	{
		if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY | TOKEN_QUERY_SOURCE, &tokenhandle) && !::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tokenhandle))
		{
			errorstr = "Unable to open a handle to the process token.";
			errorcode = "open_process_token_failed";
			winerror = ::GetLastError();
		}
	}

	// Handle output to a file.
	CubicleSoft::UTF8::File OutputFile;
	size_t y;
	if (filename != NULL)
	{
		TempVar.SetUTF8(filename);
		if (!OutputFile.Open(TempVar.GetStr(), O_CREAT | O_WRONLY | O_TRUNC))
		{
#ifdef SUBSYSTEM_WINDOWS
			InitVerboseMode();
#endif

			_tprintf(_T("Unable to open '%s' for writing.\n"), filename);

			return 1;
		}
	}

	char outputbuffer[4096];
	CubicleSoft::JSON::Serializer OutputJSON;

	OutputJSON.SetBuffer((std::uint8_t *)outputbuffer, sizeof(outputbuffer));
	OutputJSON.StartObject();

	if (errorstr != NULL)
	{
		OutputJSON.AppendBool("success", false);
		OutputJSON.AppendStr("error", errorstr);
		OutputJSON.AppendStr("errorcode", errorcode);
		DumpWinError(OutputJSON, winerror);
		OutputJSON.AppendUInt("winerrorcode", winerror);

		result = 1;
	}
	else
	{
		OutputJSON.AppendBool("success", true);

		DumpTokenInformation(OutputFile, OutputJSON, classesused, classes, rawdata, tokenhandle, 1);
	}

	OutputJSON.EndObject();
	OutputJSON.Finish();

	DumpOutput(OutputFile, OutputJSON);

	if (!OutputFile.IsOpen())  printf("\n");
	else  OutputFile.Write("\n", y);

	OutputFile.Close();

	// Let the OS clean up after this program.  It is lazy, but whatever.
	if (verbose)  _tprintf(_T("Return code = %i\n"), result);

	return result;
}

#ifdef SUBSYSTEM_WINDOWS
#ifndef UNICODE
// Swiped from:  https://stackoverflow.com/questions/291424/canonical-way-to-parse-the-command-line-into-arguments-in-plain-c-windows-api
LPSTR* CommandLineToArgvA(LPSTR lpCmdLine, INT *pNumArgs)
{
	int retval;
	retval = ::MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, lpCmdLine, -1, NULL, 0);
	if (!SUCCEEDED(retval))  return NULL;

	LPWSTR lpWideCharStr = (LPWSTR)malloc(retval * sizeof(WCHAR));
	if (lpWideCharStr == NULL)  return NULL;

	retval = ::MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, lpCmdLine, -1, lpWideCharStr, retval);
	if (!SUCCEEDED(retval))
	{
		free(lpWideCharStr);

		return NULL;
	}

	int numArgs;
	LPWSTR* args;
	args = ::CommandLineToArgvW(lpWideCharStr, &numArgs);
	free(lpWideCharStr);
	if (args == NULL)  return NULL;

	int storage = numArgs * sizeof(LPSTR);
	for (int i = 0; i < numArgs; i++)
	{
		BOOL lpUsedDefaultChar = FALSE;
		retval = ::WideCharToMultiByte(CP_ACP, 0, args[i], -1, NULL, 0, NULL, &lpUsedDefaultChar);
		if (!SUCCEEDED(retval))
		{
			::LocalFree(args);

			return NULL;
		}

		storage += retval;
	}

	LPSTR* result = (LPSTR *)::LocalAlloc(LMEM_FIXED, storage);
	if (result == NULL)
	{
		::LocalFree(args);

		return NULL;
	}

	int bufLen = storage - numArgs * sizeof(LPSTR);
	LPSTR buffer = ((LPSTR)result) + numArgs * sizeof(LPSTR);
	for (int i = 0; i < numArgs; ++ i)
	{
		BOOL lpUsedDefaultChar = FALSE;
		retval = ::WideCharToMultiByte(CP_ACP, 0, args[i], -1, buffer, bufLen, NULL, &lpUsedDefaultChar);
		if (!SUCCEEDED(retval))
		{
			::LocalFree(result);
			::LocalFree(args);

			return NULL;
		}

		result[i] = buffer;
		buffer += retval;
		bufLen -= retval;
	}

	::LocalFree(args);

	*pNumArgs = numArgs;
	return result;
}
#endif

int CALLBACK WinMain(HINSTANCE /* hInstance */, HINSTANCE /* hPrevInstance */, LPSTR lpCmdLine, int /* nCmdShow */)
{
	int argc;
	TCHAR **argv;
	int result;

#ifdef UNICODE
	argv = ::CommandLineToArgvW(::GetCommandLineW(), &argc);
#else
	argv = CommandLineToArgvA(lpCmdLine, &argc);
#endif

	if (argv == NULL)  return 0;

	result = _tmain(argc, argv);

	::LocalFree(argv);

	return result;
}
#endif
