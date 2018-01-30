#include "stdafx.h"
#include <wincred.h>
#include <wininet.h>
#include <urlhist.h>
#include <shlobj.h>
#include "boost/algorithm/string.hpp"
#include "WindowVersion.h"
#include "PasswordRecovery.h"

//////////////////////////////////////////////////////////////////////////
#pragma comment (lib, "wininet.lib")

// CInternetExplorerPasswordRecovery
//////////////////////////////////////////////////////////////////////////
#ifndef REGISTRY_KEY_IE
#define REGISTRY_KEY_IE					TEXT("SOFTWARE\\Microsoft\\Internet Explorer")
#endif

#ifndef REGISTRY_KEY_IE_STORAGE2
#define REGISTRY_KEY_IE_STORAGE2		TEXT("Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2")
#endif

#ifndef REGISTRY_KEY_IE_TYPEDURLS
#define REGISTRY_KEY_IE_TYPEDURLS		TEXT("Software\\Microsoft\\Internet Explorer\\TypedURLs")
#endif

#ifndef REGISTRY_VALUE_BUILD
#define REGISTRY_VALUE_BUILD			TEXT("Build")
#endif

#ifndef REGISTRY_VALUE_VERSION
#define REGISTRY_VALUE_VERSION			TEXT("Version")
#endif

#ifndef MAX_VALUE_NAME
#define MAX_VALUE_NAME					16384
#endif

//////////////////////////////////////////////////////////////////////////
CInternetExplorerPasswordRecovery::CInternetExplorerPasswordRecovery()
	: m_hVaultCli(NULL)
	, m_pfnVaultEnumerateVaults(NULL)
	, m_pfnVaultOpenVault(NULL)
	, m_pfnVaultFree(NULL)
	, m_pfnVaultCloseVault(NULL)
	, m_pfnVaultGetInformation(NULL)
	, m_pfnVaultEnumerateItems(NULL)
	, m_pfnVaultEnumerateItemTypes(NULL)
	, m_pfnVaultGetItem7(NULL)
	, m_pfnVaultGetItem8(NULL)
	
{
	
}

CInternetExplorerPasswordRecovery::~CInternetExplorerPasswordRecovery()
{
	CleanVaultCli();

	m_cMapHashSites.RemoveAll();
}

void CInternetExplorerPasswordRecovery::DoRecovery(IPasswordRecoveryCallback* pCallback)
{
	CString strIEBuild, strIEVersion;
	if(!GetBrowserVersion(strIEBuild, strIEVersion))
	{
		pCallback->OnRecoveryWarning(TEXT("The program can't found Internet Explorer version."));
		return;
	}

	DWORD dwIEVersion = StrToInt(strIEVersion);
	DWORD dwWinVersion = GetWindowsVersion(NULL, NULL, NULL);
	if(dwIEVersion > IE_VERSION_6)
	{
		ProcessUrlCacheData(pCallback);

		// <= Win7
		if(IS_LESS_THAN_WINDOWS_7(dwWinVersion))
		{
			ProcessAutoCompleteData(pCallback);
			//ProcessVault7Data(pCallback);
		}
		// = Win8
		else if(IS_WINDOWS_8(dwWinVersion))
		{
			ProcessVault8Data(pCallback);
		}
	}
	else
	{
		//ProcessIPStoreData(pCallback);
		//ProcessHttpAuthData(pCallback);
	}
}

DWORD CInternetExplorerPasswordRecovery::GetWindowsVersion(PDWORD pdwMajorVersion, PDWORD pdwMinorVersion, PDWORD pdwBuild)
{
	DWORD dwVerison = GetVersion();

	if(pdwMajorVersion)
	{
		*pdwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVerison)));
	}

	if(pdwMinorVersion)
	{
		*pdwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVerison)));
	}

	if(pdwBuild && dwVerison < 0x80000000)
	{  
		*pdwBuild = (DWORD)(HIWORD(dwVerison));  
	}

	return dwVerison;
}

BOOL CInternetExplorerPasswordRecovery::GetBrowserVersion(CString& strBuild, CString& strVersion)
{
	BOOL bResult = FALSE;
	HKEY hKey = NULL;
	PBYTE pData = NULL;

	do 
	{
		LSTATUS lResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, REGISTRY_KEY_IE, 0, KEY_EXECUTE, &hKey);
		if(lResult != ERROR_SUCCESS)
			break;

		DWORD dwType;
		PBYTE pData = NULL;
		DWORD dwDataSize = 0;
		lResult = RegQueryValueEx(hKey, REGISTRY_VALUE_BUILD, NULL, &dwType, pData, &dwDataSize);
		if(lResult == ERROR_MORE_DATA || lResult == ERROR_SUCCESS)
		{
			if(pData == NULL)
			{
				DWORD dwSize = dwDataSize + (1 * sizeof(TCHAR));
				pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
				if(pData)
				{
					lResult = RegQueryValueEx(hKey, REGISTRY_VALUE_BUILD, NULL, &dwType, pData, &dwDataSize);
				}
			}
		}

		if(lResult == ERROR_SUCCESS && pData != NULL)
		{
			strBuild.Format(TEXT("%s"), (LPTSTR)pData);
		}

		if(pData)
		{
			HeapFree(GetProcessHeap(), 0, pData);
			pData = NULL;
		}

		lResult = RegQueryValueEx(hKey, REGISTRY_VALUE_VERSION, NULL, &dwType, pData, &dwDataSize);
		if(lResult == ERROR_MORE_DATA || lResult == ERROR_SUCCESS)
		{
			if(pData == NULL)
			{
				DWORD dwSize = dwDataSize + (1 * sizeof(TCHAR));
				pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
				if(pData)
				{
					lResult = RegQueryValueEx(hKey, REGISTRY_VALUE_VERSION, NULL, &dwType, pData, &dwDataSize);
				}
			}
		}

		if(lResult == ERROR_SUCCESS && pData != NULL)
		{
			strVersion.Format(TEXT("%s"), (LPTSTR)pData);

			bResult = TRUE;
		}

	} while (FALSE);

	if(pData)
	{
		HeapFree(GetProcessHeap(), 0, pData);
		pData = NULL;
	}

	if(hKey)
	{
		RegCloseKey(hKey);
		hKey = NULL;
	}

	return bResult;
}

BOOL CInternetExplorerPasswordRecovery::InitVaultCli()
{
	BOOL bResult = FALSE;

	do 
	{
		if(m_hVaultCli 
			&& m_pfnVaultEnumerateVaults
			&& m_pfnVaultOpenVault 
			&& m_pfnVaultFree
			&& m_pfnVaultCloseVault
			&& m_pfnVaultGetInformation
			&& m_pfnVaultEnumerateItems
			&& m_pfnVaultEnumerateItemTypes
			&& m_pfnVaultGetItem7
			&& m_pfnVaultGetItem8
			)
		{
			bResult = TRUE;
			break;
		}

		m_hVaultCli = LoadLibrary(TEXT("vaultcli.dll"));
		if(m_hVaultCli == NULL)
			break;

		m_pfnVaultEnumerateVaults = (PfnVaultEnumerateVaults)GetProcAddress(m_hVaultCli, "VaultEnumerateVaults");
		if(m_pfnVaultEnumerateVaults == NULL)
			break;

		m_pfnVaultOpenVault = (PfnVaultOpenVault)GetProcAddress(m_hVaultCli, "VaultOpenVault");
		if(m_pfnVaultOpenVault == NULL)
			break;

		m_pfnVaultFree = (PfnVaultFree)GetProcAddress(m_hVaultCli, "VaultFree");
		if(m_pfnVaultFree == NULL)
			break;

		m_pfnVaultCloseVault = (PfnVaultCloseVault)GetProcAddress(m_hVaultCli, "VaultCloseVault");
		if(m_pfnVaultCloseVault == NULL)
			break;

		m_pfnVaultGetInformation = (PfnVaultGetInformation)GetProcAddress(m_hVaultCli, "VaultGetInformation");
		if(m_pfnVaultGetInformation == NULL)
			break;

		m_pfnVaultEnumerateItems = (PfnVaultEnumerateItems)GetProcAddress(m_hVaultCli, "VaultEnumerateItems");
		if(m_pfnVaultEnumerateItems == NULL)
			break;

		m_pfnVaultEnumerateItemTypes = (PfnVaultEnumerateItemTypes)GetProcAddress(m_hVaultCli, "VaultEnumerateItemTypes");
		if(m_pfnVaultEnumerateItemTypes == NULL)
			break;

		m_pfnVaultGetItem7 = (PfnVaultGetItem7)GetProcAddress(m_hVaultCli, "VaultGetItem");
		if(m_pfnVaultGetItem7 == NULL)
			break;

		m_pfnVaultGetItem8 = (PfnVaultGetItem8)GetProcAddress(m_hVaultCli, "VaultGetItem");
		if(m_pfnVaultGetItem8 == NULL)
			break;

		bResult = TRUE;

	} while (FALSE);

	return bResult;
}

BOOL CInternetExplorerPasswordRecovery::CleanVaultCli()
{
	if(m_hVaultCli == NULL)
		return FALSE;

	FreeLibrary(m_hVaultCli);
	m_hVaultCli = NULL;

	return TRUE;
}

BOOL CInternetExplorerPasswordRecovery::InitHashSiteMap()
{
	BOOL bResult = FALSE;

	do 
	{
		if(!m_cMapHashSites.IsEmpty())
		{
			bResult = TRUE;
			break;
		}

		POSITION pos = m_cMatchSites.GetHeadPosition();
		while(pos != NULL)
		{
			CString strSite = m_cMatchSites.GetNext(pos);
			strSite.AppendChar(TEXT('/'));
			strSite.MakeLower();

			DWORD dwDataSize = (strSite.GetLength() + 1) * sizeof(TCHAR);

			CString strHash;
			bResult = m_cPasswordDecryptor.GetHashString(strSite.GetBuffer(0), dwDataSize, strHash);
			strSite.ReleaseBuffer();

			if(!bResult)
			{
				m_cMapHashSites.RemoveAll();
				break;
			}

			m_cMapHashSites.SetAt(strHash, strSite);
		}
	} while (FALSE);

	return bResult;
}

BOOL CInternetExplorerPasswordRecovery::HasHash(const CString& strHash)
{
	POSITION pos = m_cMapHashSites.GetStartPosition();
	while(pos != NULL)
	{
		CString strKey, strValue;
		m_cMapHashSites.GetNextAssoc(pos, strKey, strValue);
		if(strKey.IsEmpty())
			continue;

		if(lstrcmp(strKey, strHash) == 0)
			return TRUE;
	}

	return FALSE;
}

BOOL CInternetExplorerPasswordRecovery::GetSite(const CString& strHash, CString& strSite)
{
	POSITION pos = m_cMapHashSites.GetStartPosition();
	while(pos != NULL)
	{
		CString strKey, strValue;
		m_cMapHashSites.GetNextAssoc(pos, strKey, strValue);
		if(strKey.IsEmpty())
			continue;

		if(lstrcmp(strKey, strHash) == 0)
		{
			strSite.Format(TEXT("%s"), strValue);
			return TRUE;
		}
	}

	return FALSE;
}

VOID CInternetExplorerPasswordRecovery::ProcessUrlCacheData(IPasswordRecoveryCallback* pCallback)
{
	CStringArray cUrlArray;
	GetRegistryTypedURLs(cUrlArray);
	GetHistoryURLs(cUrlArray);

	{
		HANDLE hEntry;   
		DWORD dwSize;
		BYTE buffer[8192];
		LPINTERNET_CACHE_ENTRY_INFO info = (LPINTERNET_CACHE_ENTRY_INFO) buffer;

		dwSize = 8192;
		hEntry = FindFirstUrlCacheEntry(NULL, info, &dwSize);

		if (hEntry != NULL)
		{
			do
			{
				if (info->CacheEntryType != COOKIE_CACHE_ENTRY) 
				{
					cUrlArray.Add(info->lpszSourceUrlName);
				}

				if(!boost::algorithm::istarts_with(info->lpszSourceUrlName, TEXT("http")))
					continue;

				if(info->lpszLocalFileName == NULL)
					continue;

				if(!boost::algorithm::iends_with(info->lpszLocalFileName, TEXT("htm")))
					continue;

				if(!boost::algorithm::iends_with(info->lpszLocalFileName, TEXT("html")))
					continue;

				dwSize = 8192;

			} while (FindNextUrlCacheEntry(hEntry, info, &dwSize));

			FindCloseUrlCache(hEntry);
		}
	}
}

VOID CInternetExplorerPasswordRecovery::ProcessAutoCompleteData(IPasswordRecoveryCallback* pCallback)
{
	BOOL bResult = FALSE;
	HKEY hKey = NULL;
	PBYTE pData = NULL;

	do 
	{
		if(!InitHashSiteMap())
			break;

		LSTATUS lResult = RegOpenKeyEx(HKEY_CURRENT_USER, REGISTRY_KEY_IE_STORAGE2, 0, KEY_QUERY_VALUE, &hKey);
		if(lResult != ERROR_SUCCESS)
			break;

		TCHAR szClassName[MAX_PATH] = TEXT("");
		DWORD dwClassName = MAX_PATH;
		DWORD dwSubKeys = 0;
		DWORD dwMaxSubKey;
		DWORD dwMaxClass;
		DWORD dwValues;
		DWORD dwMaxValue;
		DWORD dwMaxValueData;
		DWORD dwSecurityDescriptor;
		FILETIME ftLastWriteTime;
		lResult = RegQueryInfoKey(
			hKey,
			szClassName,
			&dwClassName,
			NULL,
			&dwSubKeys,
			&dwMaxSubKey,
			&dwMaxClass,
			&dwValues,
			&dwMaxValue,
			&dwMaxValueData,
			&dwSecurityDescriptor,
			&ftLastWriteTime);
		if(dwValues)
		{
			TCHAR szValueName[MAX_VALUE_NAME];
			DWORD dwValueNameSize = MAX_VALUE_NAME;
			DWORD dwType = 0;
			PBYTE pData = NULL;
			DWORD dwDataSize = 0;
			for(DWORD i = 0; i < dwValues; i++) 
			{
				if(pData)
				{
					HeapFree(GetProcessHeap(), 0, pData);
					pData = NULL;
				}

				lResult = RegEnumValueW(hKey, i, szValueName, &dwValueNameSize, 0, 0, 0, 0);
				if(lResult != ERROR_NO_MORE_ITEMS && lResult != ERROR_SUCCESS)
					continue;

				if(!HasHash(szValueName))
					continue;

				CString strSiteAddress;
				if(!GetSite(szValueName, strSiteAddress))
					continue;

				lResult = RegQueryValueEx(hKey, szValueName, NULL, &dwType, pData, &dwDataSize);
				if(lResult == ERROR_MORE_DATA || lResult == ERROR_SUCCESS)
				{
					if(pData == NULL)
					{
						DWORD dwSize = dwDataSize + (1 * sizeof(TCHAR));
						pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
						if(pData)
						{
							lResult = RegQueryValueEx(hKey, szValueName, NULL, &dwType, pData, &dwDataSize);
						}
					}
				}

				if(lResult == ERROR_SUCCESS && pData != NULL)
				{
#ifdef _UNICODE
					DWORD dwOptionalSize = (strSiteAddress.GetLength() + 1) * 2;
#else
					DWORD dwOptionalSize = strSiteAddress.GetLength() + 1;
#endif
					BOOL bDecrypt = m_cPasswordDecryptor.Decrypt(pData, dwDataSize, strSiteAddress.GetBuffer(0), dwOptionalSize);
					strSiteAddress.ReleaseBuffer();
					HeapFree(GetProcessHeap(), 0, pData);
					pData = NULL;
					if(!bDecrypt) continue;

					DWORD dwDecryptDataSize = 0;
					PVOID pdwDecryptData = m_cPasswordDecryptor.GetDecryptData(&dwDecryptDataSize);
					if(pdwDecryptData == NULL || dwDecryptDataSize == 0)
						continue;

					AutoComplteSecretHeader* pIEAutoHeader = (AutoComplteSecretHeader*)pdwDecryptData;
					if(dwDecryptDataSize >= (pIEAutoHeader->Size + pIEAutoHeader->SecretInfoSize + pIEAutoHeader->SecretSize))
					{
						DWORD dwTotalSecrets = pIEAutoHeader->SecretHeader.TotalSecrets / 2;

						SecretEntry *pSecretEntry = (SecretEntry*)((PBYTE)pdwDecryptData + sizeof(AutoComplteSecretHeader));
						PBYTE pSecretEntryOffset = (PBYTE)((PBYTE)pdwDecryptData + pIEAutoHeader->Size + pIEAutoHeader->SecretInfoSize);
						PBYTE pCurrentOffset;
						for(DWORD i = 0; i < dwTotalSecrets; i++)
						{
							pCurrentOffset = pSecretEntryOffset + pSecretEntry->Offset;
							LPTSTR lpszUserName = (LPTSTR)pCurrentOffset;

							pSecretEntry++;

							pCurrentOffset = pSecretEntryOffset + pSecretEntry->Offset;
							LPTSTR lpszPassword = (LPTSTR)pCurrentOffset;

							if(pCallback)
							{
								pCallback->OnRecoveryRecord(strSiteAddress, lpszUserName, lpszPassword, 0);
							}

							pSecretEntry++;
						}
					}
				}
			}
		}
	} while (FALSE);

	if(hKey)
	{
		RegCloseKey(hKey);
		hKey = NULL;
	}
}

VOID CInternetExplorerPasswordRecovery::ProcessVault7Data(IPasswordRecoveryCallback* pCallback)
{
	if(!InitVaultCli())
		return;

	DWORD dwVaults;
	GUID *ppVaultGuids = NULL;
	DWORD dwStatus = m_pfnVaultEnumerateVaults(NULL, &dwVaults, &ppVaultGuids);
	if (dwStatus != ERROR_SUCCESS)
		return;

	PVAULT_ITEM_7 pItem = NULL;
	PVAULT_ITEM_7 ppCredentials = NULL;
	for (DWORD i = 0; i < dwVaults; i++)
	{
		if(RtlEqualMemory((PVOID)&ppVaultGuids[i], Vault_WebCredential_ID, sizeof(GUID)))
			continue;

		HVAULT hVault = NULL;
		dwStatus = m_pfnVaultOpenVault(&ppVaultGuids[i], 0, &hVault);
		if (dwStatus != ERROR_SUCCESS)
			continue;

		PVOID ppItems = NULL;
		DWORD dwItems = 0;
		dwStatus = m_pfnVaultEnumerateItems(hVault, 0, &dwItems, &ppItems);
		if (dwStatus != ERROR_SUCCESS)
			continue;

		if(dwItems == 0 && ppItems)
		{
			m_pfnVaultFree(&ppItems);
			ppItems = NULL;
			continue;
		}

		for (DWORD j = 0; j < dwItems; j++)
		{
			pItem = (PVAULT_ITEM_7)((PBYTE)ppItems + j * sizeof(VAULT_ITEM_7));
			if (pItem == NULL || RtlEqualMemory(&pItem->SchemaId, VaultFile, sizeof(GUID)))
				continue;

			ppCredentials = NULL;
			dwStatus = m_pfnVaultGetItem7(hVault, &pItem[j].SchemaId, pItem[j].Ressource, pItem[j].Identity, NULL, 0, &ppCredentials);
			if(dwStatus != ERROR_SUCCESS || ppCredentials == NULL)
				continue;

			LPWSTR lpszAccount = pItem->FriendlyName;
			LPWSTR lpszSiteAddress = pItem->Ressource->data.String;
			LPWSTR lpszLogin = pItem->Identity->data.String;
			LPWSTR lpszPassword = ppCredentials->Authenticator->data.String;
			DWORD dwDataCreated = 0;

			FILETIME lt;
			if(FileTimeToLocalFileTime(&pItem->LastWritten, &lt))
			{
				WORD wFatDate, wFatTime;
				if(FileTimeToDosDateTime(&lt, &wFatDate, &wFatTime))
				{
					dwDataCreated = MAKELONG(wFatDate, wFatTime);
				}
			}

			if(pCallback)
			{
#ifdef _UNICODE
				pCallback->OnRecoveryRecord(lpszSiteAddress, lpszLogin, lpszPassword, dwDataCreated);
#else
				pCallback->OnRecoveryRecord(
					StringHelper::ws2s(lpszSiteAddress, CP_ACP).c_str(), 
					StringHelper::ws2s(lpszLogin, CP_ACP).c_str(), 
					StringHelper::ws2s(lpszPassword, CP_ACP).c_str(), 
					dwDataCreated);
#endif // _UNICODE

			}

			m_pfnVaultFree(ppCredentials);
		}

		if(ppItems)
		{
			m_pfnVaultFree(&ppItems);
			ppItems = NULL;
		}
	}

	if(ppVaultGuids)
	{
		m_pfnVaultFree(&ppVaultGuids);
		ppVaultGuids = NULL;
	}
}

VOID CInternetExplorerPasswordRecovery::ProcessVault8Data(IPasswordRecoveryCallback* pCallback)
{
	if(!InitVaultCli())
		return;

	DWORD dwVaults;
	GUID *ppVaultGuids = NULL;
	DWORD dwStatus = m_pfnVaultEnumerateVaults(NULL, &dwVaults, &ppVaultGuids);
	if (dwStatus != ERROR_SUCCESS)
		return;

	for (DWORD i = 0; i < dwVaults; i++)
	{
		if(memcmp((PVOID)&ppVaultGuids[i], Vault_WebCredential_ID, sizeof(GUID)))
			continue;

		HVAULT hVault = NULL;
		dwStatus = m_pfnVaultOpenVault(&ppVaultGuids[i], 0, &hVault);
		if (dwStatus != ERROR_SUCCESS)
			continue;

		PVOID ppItems = NULL;
		DWORD dwItems = 0;
		dwStatus = m_pfnVaultEnumerateItems(hVault, 0, &dwItems, &ppItems);
		if (dwStatus != ERROR_SUCCESS)
			continue;

		if(dwItems == 0 && ppItems)
		{
			m_pfnVaultFree(&ppItems);
			ppItems = NULL;
			continue;
		}

		for (DWORD j = 0; j < dwItems; j++)
		{
			PVAULT_ITEM_8 pItem = (PVAULT_ITEM_8)((PBYTE)ppItems + j * sizeof(PVAULT_ITEM_8));
			if (pItem == NULL || memcmp (&pItem->SchemaId, VaultFile, sizeof(GUID)))
				continue;

			PVAULT_ITEM_8 ppCredentials = NULL;
			dwStatus = m_pfnVaultGetItem8(hVault, &pItem[j].SchemaId, pItem[j].Ressource, pItem[j].Identity, NULL, NULL, 0, &ppCredentials);
			if(dwStatus != ERROR_SUCCESS || ppCredentials == NULL)
				continue;

			LPWSTR lpszAccount = pItem->FriendlyName;
			LPWSTR lpszSiteAddress = pItem->Ressource->data.String;
			LPWSTR lpszLogin = pItem->Identity->data.String;
			LPWSTR lpszPassword = ppCredentials->Authenticator->data.String;
			DWORD dwDataCreated = 0;

			FILETIME lt;
			if(FileTimeToLocalFileTime(&pItem->LastWritten, &lt))
			{
				WORD wFatDate, wFatTime;
				if(FileTimeToDosDateTime(&lt, &wFatDate, &wFatTime))
				{
					dwDataCreated = MAKELONG(wFatDate, wFatTime);
				}
			}

			if(pCallback)
			{
#ifdef _UNICODE
				pCallback->OnRecoveryRecord(lpszSiteAddress, lpszLogin, lpszPassword, dwDataCreated);
#else
				pCallback->OnRecoveryRecord(
					StringHelper::ws2s(lpszSiteAddress, CP_ACP).c_str(), 
					StringHelper::ws2s(lpszLogin, CP_ACP).c_str(), 
					StringHelper::ws2s(lpszPassword, CP_ACP).c_str(), 
					dwDataCreated);
#endif // _UNICODE

			}

			m_pfnVaultFree(ppCredentials);
		}

		if(ppItems)
		{
			m_pfnVaultFree(&ppItems);
			ppItems = NULL;
		}
	}

	if(ppVaultGuids)
	{
		m_pfnVaultFree(&ppVaultGuids);
		ppVaultGuids = NULL;
	}
}

void CInternetExplorerPasswordRecovery::ProcessIPStoreData(IPasswordRecoveryCallback* pCallback)
{
	/*
	typedef HRESULT (WINAPI *PfnPStoreCreateInstance)(IPStore **, DWORD, DWORD, DWORD);

	HMODULE hModule = LoadLibrary(TEXT("pstorec.dll"));
	PfnPStoreCreateInstance pfnPStoreCreateInstance = (PfnPStoreCreateInstance)GetProcAddress(hModule, "PStoreCreateInstance");
	IPStorePtr pPStore; 
	HRESULT hr = pPStoreCreateInstance(&pPStore, 0, 0, 0); 
	IEnumPStoreTypesPtr pEnumPStoreTypes; 
	hr = pPStore->EnumTypes(0, 0, &pEnumPStoreTypes);
	hr = PStore->ReadItem(0, &TypeGUID, &SubTypeGUID, itemName, &psDataLen, &psData, pstiinfo, 0); 
	.....
	*/
}

VOID CInternetExplorerPasswordRecovery::ProcessHttpAuthData(IPasswordRecoveryCallback* pCallback)
{
	DATA_BLOB DataIn;
	DATA_BLOB DataOut;
	DATA_BLOB DataOptional;
	CHAR szCredentials[1024];
	CHAR szUsername[1024];
	CHAR szPassword[1024];
	WCHAR szTmpSalt[37];
	PCHAR pszSalt = {"abe2869f-9b47-4cd9-a358-c22904dba7f7"};

	for(int i = 0; i < 37; i++)
	{
		szTmpSalt[i] = (short int)(pszSalt[i] * 4);
	}

	DataOptional.pbData = (BYTE *)&szTmpSalt;
	DataOptional.cbData = 74;

	DWORD dwCount;
	PCREDENTIAL* pCredential;

	if(CredEnumerate(NULL,0,&dwCount,&pCredential))
	{
		for(DWORD i = 0; i < dwCount; i++)
		{
			if( (pCredential[i]->Type == 1) 
				&& _tcsnicmp(pCredential[i]->TargetName, TEXT("Microsoft_WinInet_"), lstrlen(TEXT("Microsoft_WinInet_"))) == 0 )
			{
				DataIn.pbData = (BYTE *)pCredential[i]->CredentialBlob;
				DataIn.cbData = pCredential[i]->CredentialBlobSize;

				if(CryptUnprotectData(&DataIn, NULL, &DataOptional, NULL, NULL, 0, &DataOut))
				{
					sprintf_s(szCredentials, 1024, "%S", DataOut.pbData);

					PCHAR p = strchr(szCredentials, ':');
					*p = '\0';
					strcpy_s(szUsername, 1024, szCredentials);
					p++;
					strcpy_s(szPassword, 1024, p);

					if(pCallback)
					{
						pCallback->OnRecoveryRecord((LPCTSTR)(&pCredential[i]->TargetName), 
							StringHelper::s2ws(szUsername, CP_ACP).c_str(), 
							StringHelper::s2ws(szPassword, CP_ACP).c_str(), 
							0);
					}
				}
			}
		}

		CredFree(pCredential);
	}
}


BOOL CInternetExplorerPasswordRecovery::GetRegistryTypedURLs(CStringArray& cUrlArray)
{
	LSTATUS lResult = ERROR_NO_MORE_ITEMS;
	HKEY hKey = NULL;
	PBYTE pData = NULL;
	
	// CLSID_CUrlHistory 3C374A40-BAE4-11CF-BF7D-00AA006946EE

	do 
	{
		if(!InitHashSiteMap())
			break;

		LSTATUS lResult = RegOpenKeyEx(HKEY_CURRENT_USER, REGISTRY_KEY_IE_TYPEDURLS, 0, KEY_QUERY_VALUE, &hKey);
		if(lResult != ERROR_SUCCESS)
			break;

		TCHAR szClassName[MAX_PATH] = TEXT("");
		DWORD dwClassName = MAX_PATH;
		DWORD dwSubKeys = 0;
		DWORD dwMaxSubKey;
		DWORD dwMaxClass;
		DWORD dwValues;
		DWORD dwMaxValue;
		DWORD dwMaxValueData;
		DWORD dwSecurityDescriptor;
		FILETIME ftLastWriteTime;
		lResult = RegQueryInfoKey(
			hKey,
			szClassName,
			&dwClassName,
			NULL,
			&dwSubKeys,
			&dwMaxSubKey,
			&dwMaxClass,
			&dwValues,
			&dwMaxValue,
			&dwMaxValueData,
			&dwSecurityDescriptor,
			&ftLastWriteTime);
		if(dwValues)
		{
			TCHAR szValueName[MAX_VALUE_NAME];
			DWORD dwValueNameSize = MAX_VALUE_NAME;
			DWORD dwType = 0;
			PBYTE pData = NULL;
			DWORD dwDataSize = 0;
			for(DWORD i = 0; i < dwValues; i++) 
			{
				if(pData)
				{
					HeapFree(GetProcessHeap(), 0, pData);
					pData = NULL;
				}

				lResult = RegEnumValueW(hKey, i, szValueName, &dwValueNameSize, 0, 0, 0, 0);
				if(lResult != ERROR_NO_MORE_ITEMS && lResult != ERROR_SUCCESS)
					continue;

				lResult = RegQueryValueEx(hKey, szValueName, NULL, &dwType, pData, &dwDataSize);
				if(lResult == ERROR_MORE_DATA || lResult == ERROR_SUCCESS)
				{
					if(pData == NULL)
					{
						DWORD dwSize = dwDataSize + (1 * sizeof(TCHAR));
						pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
						if(pData)
						{
							lResult = RegQueryValueEx(hKey, szValueName, NULL, &dwType, pData, &dwDataSize);
						}
					}
				}

				if(lResult == ERROR_SUCCESS && pData != NULL)
				{
					CString strUrl;
					strUrl.Format(TEXT("%s"), pData);

					cUrlArray.Add(strUrl);

					HeapFree(GetProcessHeap(), 0, pData);
					pData = NULL;
				}
			}
		}
	} while (FALSE);

	if(hKey)
	{
		RegCloseKey(hKey);
		hKey = NULL;
	}
	
	return lResult == ERROR_SUCCESS;
}

BOOL CInternetExplorerPasswordRecovery::GetHistoryURLs(CStringArray& cUrlArray)
{
	BOOL bResult = FALSE;
	IUrlHistoryStg2* pUrlHistoryStg2 = NULL;
	IEnumSTATURL* pEnumURL = NULL;

	do 
	{
		HRESULT hr = CoCreateInstance(CLSID_CUrlHistory,
			NULL, CLSCTX_INPROC, IID_IUrlHistoryStg2,
			(void**)&pUrlHistoryStg2);
		if(!SUCCEEDED(hr))
			break;

		hr = pUrlHistoryStg2->EnumUrls(&pEnumURL);
		if(!SUCCEEDED(hr))
			break;

		STATURL suURL;
		suURL.cbSize = sizeof(STATURL);

		ULONG pceltFetched;
		while((hr = pEnumURL->Next(1, &suURL, &pceltFetched)) == S_OK)
		{
#ifdef _UNICODE
			cUrlArray.Add(suURL.pwcsUrl);
#else
			cUrlArray.Add(StringHelper::ws2s(suURL.pwcsUrl, CP_ACP).c_str());
#endif
		}

		bResult = TRUE;

	} while (FALSE);

	if(pEnumURL)
	{
		pEnumURL->Release();
		pEnumURL = NULL;
	}

	if(pUrlHistoryStg2)
	{
		pUrlHistoryStg2->Release();
		pUrlHistoryStg2 = NULL;
	}
	
	return bResult;
}

BOOL CInternetExplorerPasswordRecovery::GetCacheHtmlInfo(const CString& strFilePath, CString& strLogin, CString& strPassword)
{
	/************************************************************************
	* step 1. Open %strFilePath% File 
	* step 2. Get %strFilePath% File Content
	* step 3. Search String :
				<input name=\"login\">
				<input name=\"pwd\">
				type=\"text\
				type=\"radio\
				type=\"search\
				type=\"checkbox\
				type=\"password\
	************************************************************************/

	return TRUE;
}