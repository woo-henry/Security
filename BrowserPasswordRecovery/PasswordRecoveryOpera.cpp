#include "stdafx.h"
#include "PasswordRecovery.h"

// COperaPasswordRecovery
//////////////////////////////////////////////////////////////////////////
#ifndef PATH_NAME_OPERA
#define PATH_NAME_OPERA					TEXT("Opera")
#endif

#ifndef PATH_NAME_OPERA_BETA9
#define PATH_NAME_OPERA_BETA9			TEXT("Opera Beta 9")
#endif

#ifndef FILE_NAME_PROFILE_ACCOUNTS
#define FILE_NAME_PROFILE_ACCOUNTS		TEXT("accounts.ini")
#endif

#ifndef FILE_NAME_WAND_DAT
#define FILE_NAME_WAND_DAT				TEXT("wand.dat")
#endif

#ifndef PROFILE_SECTION_EMAIL
#define PROFILE_SECTION_EMAIL			TEXT("email")
#endif

#ifndef PROFILE_KEY_SERVERNAME
#define PROFILE_KEY_SERVERNAME			TEXT("Incoming Servername")
#endif

#ifndef PROFILE_KEY_USERNAME
#define PROFILE_KEY_USERNAME			TEXT("Incoming Username")
#endif

#ifndef PROFILE_KEY_PASSWORD
#define PROFILE_KEY_PASSWORD			TEXT("Incoming Password")
#endif

#ifndef MAX_SECTION_NAME
#define MAX_SECTION_NAME				4096
#endif

void COperaPasswordRecovery::DoRecovery(IPasswordRecoveryCallback* pCallback)
{
	// [Windows NT/2K/2k3/XP]
	TCHAR szCommonAppDataPath[MAX_PATH];
	if(SUCCEEDED(SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT, szCommonAppDataPath)))
	{
		ProcessProfileAccountData(pCallback, szCommonAppDataPath);
		ProcessWandData(pCallback, szCommonAppDataPath);
	}
	else
	{
		pCallback->OnRecoveryWarning(TEXT("The program can't found Opera common appdata directory."));
	}
	
	// [Windows Vista/Windows 7] 
	TCHAR szAppDataPath[MAX_PATH];
	if(SUCCEEDED(SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, SHGFP_TYPE_CURRENT, szAppDataPath)))
	{
		ProcessProfileAccountData(pCallback, szAppDataPath);
		ProcessWandData(pCallback, szAppDataPath);
	}
	else
	{
		pCallback->OnRecoveryWarning(TEXT("The program can't found Opera appdata directory."));
	}
}

void COperaPasswordRecovery::ProcessProfileAccountData(IPasswordRecoveryCallback* pCallback, LPCTSTR lpszPath)
{
	CStringList folderList;
	folderList.AddTail(PATH_NAME_OPERA);
	folderList.AddTail(PATH_NAME_OPERA_BETA9);

	do 
	{
		CString strFolder = folderList.RemoveHead();
		if(strFolder.IsEmpty())
			continue;

		CString strProfilePath;
		strProfilePath.Format(TEXT("%s\\%s\\%s"), lpszPath, strFolder, FILE_NAME_PROFILE_ACCOUNTS);
		if(!PathFileExists(strProfilePath))
			continue;

		int nPos = 0;
		TCHAR szSectionNames[MAX_SECTION_NAME] = {0};
		TCHAR szSectionName[MAX_PATH] = {0};
		DWORD dwResult = GetPrivateProfileSectionNamesW(szSectionNames, MAX_SECTION_NAME, strProfilePath);
		for(int i = 0; i < MAX_SECTION_NAME - 1; i++)
		{
			if(szSectionNames[i] == 0)
			{
				for(int j = nPos; j <= i; j++)
				{
					szSectionName[j - nPos] = szSectionNames[j];
				}

				CString strSectionName(szSectionName);
				strSectionName.MakeLower();
				int nIndex = strSectionName.Find(PROFILE_SECTION_EMAIL);
				if(nIndex >= 0)
				{
					TCHAR szSiteAddress[MAX_PATH] = {0};
					dwResult = GetPrivateProfileString(strSectionName, PROFILE_KEY_SERVERNAME, 
						TEXT(""), szSiteAddress, MAX_PATH, strProfilePath);
					if(dwResult <= 0)
						break;

					CString strSiteAddress(szSiteAddress);
					RemoveLastPathSymbol(strSiteAddress);
					if(!MatchSiteAddress(strSiteAddress))
						break;

					TCHAR szLogin[MAX_PATH] = {0};
					dwResult = GetPrivateProfileString(strSectionName, PROFILE_KEY_USERNAME, 
						TEXT(""), szLogin, MAX_PATH, strProfilePath);
					if(dwResult <= 0)
						break;

					TCHAR szPassword[MAX_PATH] = {0};
					dwResult = GetPrivateProfileString(strSectionName, PROFILE_KEY_PASSWORD, 
						TEXT(""), szPassword, MAX_PATH, strProfilePath);
					if(dwResult <= 0)
						break;

					/*
						szLogin and szPassword Need use Delphi TDCP_3des Decrypt 
					*/
					if(pCallback)
					{
						pCallback->OnRecoveryRecord(strSiteAddress, szLogin, szPassword, 0);
					}
				}

				if(szSectionNames[i + 1] == 0)
					break;

				nPos = i + 1;
			}
		}

	} while (!folderList.IsEmpty());
}

/*
	Password Wand file for each of the stored entry in the following order
		Login URL of website
		Main URL of website
		Username field ID
		Username
		Password field ID
		Password
*/
void COperaPasswordRecovery::ProcessWandData(IPasswordRecoveryCallback* pCallback, LPCTSTR lpszPath)
{
	CStringList fileList;
	fileList.AddTail(PATH_NAME_OPERA);
	fileList.AddTail(PATH_NAME_OPERA_BETA9);

	do 
	{
		CString strOperaFolder = fileList.RemoveHead();
		if(strOperaFolder.IsEmpty())
			continue;

		CString strAccounts;
		strAccounts.Format(TEXT("%s\\%s\\%s"), lpszPath, strOperaFolder, FILE_NAME_WAND_DAT);
		if(!PathFileExists(strAccounts))
			continue;

		HANDLE hFile = CreateFile(lpszPath,
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL,
			OPEN_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL);

		if(hFile == INVALID_HANDLE_VALUE)
			break;

		DWORD dwFileSizeHigh;
		DWORD dwFileSize = GetFileSize(hFile, &dwFileSizeHigh);
		PCHAR pWandData = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
		if(pWandData == NULL)
		{
			CloseHandle(hFile);
			continue;
		}

		// 按照上面的格式解析数据，解析出的Username和Password使用3des解密

	} while (!fileList.IsEmpty());
}