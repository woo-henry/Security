#include "stdafx.h"
#include <string>
#include <vector>
#include <boost/algorithm/string.hpp>
#include <sqlite3/sqlite3.h>
#include "PasswordRecovery.h"

// CFirefoxPasswordRecovery
//////////////////////////////////////////////////////////////////////////
#ifndef REGISTRY_KEY_FIREFOX
#define REGISTRY_KEY_FIREFOX			TEXT("Software\\Mozilla")
#endif

#ifndef REGISTRY_VALUE_FIREFOX
#define REGISTRY_VALUE_FIREFOX			TEXT("PathToExe")
#endif

#ifndef FILE_PATH_FIREFOX
#define FILE_PATH_FIREFOX				TEXT("Mozilla\\Firefox")
#endif

#ifndef FILE_PROFILE_FIREFOX
#define FILE_PROFILE_FIREFOX			TEXT("profiles.ini")
#endif

#ifndef PROFILE_SECTION_PROFILE
#define PROFILE_SECTION_PROFILE			TEXT("profile")
#endif

#ifndef PROFILE_KEY_PATH
#define PROFILE_KEY_PATH				TEXT("Path")
#endif

#ifndef ENVIRONMENT_NAME_PATH
#define ENVIRONMENT_NAME_PATH			TEXT("PATH")
#endif

#ifndef SIGN_ON_VERSION_LESS_2
#define SIGN_ON_VERSION_LESS_2			"#2c"
#endif

#ifndef SIGN_ON_VERSION_2_0BETWEEN3_0
#define SIGN_ON_VERSION_2_0BETWEEN3_0	"#2d"
#endif

#ifndef SIGN_ON_VERSION_3_0BETWEEN3_5
#define SIGN_ON_VERSION_3_0BETWEEN3_5	"#2e"
#endif

#ifndef FULL_STOP_CHAR
#define FULL_STOP_CHAR					'.'
#endif

#ifndef FULL_STOP_STR
#define FULL_STOP_STR					TEXT(".")
#endif

#ifndef DASHED_LINE_STR
#define DASHED_LINE_STR					TEXT("---")
#endif

#ifndef MATCH_STRING
#define MATCH_STRING					TEXT("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
#endif

#ifndef MAX_KEY_LENGTH
#define MAX_KEY_LENGTH					255
#endif

#ifndef MAX_VALUE_NAME
#define MAX_VALUE_NAME					16384
#endif

#ifndef MAX_SECTION_NAME
#define MAX_SECTION_NAME				4096
#endif

#ifndef ENV_VARIABLE_LENGTH
#define ENV_VARIABLE_LENGTH				16384
#endif

#ifndef INDEX_SITE_ADDRESS
#define INDEX_SITE_ADDRESS				0
#endif

#ifndef INDEX_LOGIN
#define INDEX_LOGIN						2
#endif

#ifndef INDEX_PASSWORD
#define INDEX_PASSWORD					4
#endif

void CFirefoxPasswordRecovery::DoRecovery(IPasswordRecoveryCallback* pCallback)
{
	CString strInstallPath;
	if(!GetInstallPath(pCallback, HKEY_CURRENT_USER, strInstallPath))
	{
		if(!GetInstallPath(pCallback, HKEY_LOCAL_MACHINE, strInstallPath))
		{
			pCallback->OnRecoveryWarning(TEXT("The program can't found Mozilla Firefox install directory."));
			return;
		}
	}

	if(!SetEnvironmentPath(pCallback, strInstallPath))
	{
		pCallback->OnRecoveryWarning(TEXT("The program can't set Mozilla Firefox install path to system path."));
		return;
	}

	CString strProfilePath;
	if(!GetProfilePath(pCallback, strProfilePath))
	{
		pCallback->OnRecoveryWarning(TEXT("The program can't found Mozilla Firefox profiles directory."));
		return;
	}

	if(!m_cPasswordDecryptor.LoadDecryptModule(strInstallPath, strProfilePath))
	{
		pCallback->OnRecoveryWarning(TEXT("The program can't load Mozilla Firefox decrypt module."));
		return;
	}

	/*
	Facebook Password Recovery Master 没有实现 For Firefox v32.x and above
	// %AppData%\\%Profile%\\logins.json
	{
		TCHAR szSignonsPath[MAX_PATH] = {0};
		lstrcpy(szSignonsPath, strProfilePath);
		PathAppend(szSignonsPath, TEXT("\\logins.json"));
		if(PathFileExists(szSignonsPath))
		{
			ProcessVersionAbove32_0(pCallback, szSignonsPath);
		}
	}
	*/

	// %AppData%\\%Profile%\\signons.sqlite
	{
		TCHAR szSignonsPath[MAX_PATH] = {0};
		lstrcpy(szSignonsPath, strProfilePath);
		PathAppend(szSignonsPath, TEXT("\\signons.sqlite"));
		if(PathFileExists(szSignonsPath))
		{
			ProcessVersion3_5Between32_0(pCallback, szSignonsPath);
		}
	}

	// %AppData%\\%Profile%\\signons.txt
	{
		TCHAR szSignonsPath[MAX_PATH] = {0};
		lstrcpy(szSignonsPath, strProfilePath);
		PathAppend(szSignonsPath, TEXT("\\signons.txt"));
		if(PathFileExists(szSignonsPath))
		{
			ProcessVersionLess2_0(pCallback, szSignonsPath);
		}
	}

	// %AppData%\\%Profile%\\signons2.txt
	{
		TCHAR szSignonsPath[MAX_PATH] = {0};
		lstrcpy(szSignonsPath, strProfilePath);
		PathAppend(szSignonsPath, TEXT("\\signons2.txt"));
		if(PathFileExists(szSignonsPath))
		{
			ProcessVersion2_0Between3_0(pCallback, szSignonsPath);
		}
	}

	// %AppData%\\%Profile%\\signons3.txt
	{
		TCHAR szSignonsPath[MAX_PATH] = {0};
		lstrcpy(szSignonsPath, strProfilePath);
		PathAppend(szSignonsPath, TEXT("\\signons3.txt"));
		if(PathFileExists(szSignonsPath))
		{
			ProcessVersion3_0Between3_5(pCallback, szSignonsPath);
		}
	}
}

BOOL CFirefoxPasswordRecovery::GetInstallPath(IPasswordRecoveryCallback* pCallback, HKEY hRootKey, CString& strPath)
{
	BOOL bResult = FALSE;

	CStringList listRegistries;
	listRegistries.AddHead(REGISTRY_KEY_FIREFOX);

	do 
	{
		CString strSubKey = listRegistries.RemoveTail();
		if(strSubKey.IsEmpty())
			continue;

		HKEY hKey;
		LSTATUS lResult = RegOpenKey(hRootKey, strSubKey, &hKey);
		if(lResult != ERROR_SUCCESS)
			continue;

		DWORD dwType;
		PBYTE pData = NULL;
		DWORD dwDataSize = 0;
		lResult = RegQueryValueEx(hKey, REGISTRY_VALUE_FIREFOX, NULL, &dwType, pData, &dwDataSize);
		if(lResult == ERROR_MORE_DATA || lResult == ERROR_SUCCESS)
		{
			if(pData == NULL)
			{
				DWORD dwSize = dwDataSize + (1 * sizeof(TCHAR));
				pData = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
				if(pData)
				{
					lResult = RegQueryValueEx(hKey, REGISTRY_VALUE_FIREFOX, NULL, &dwType, pData, &dwDataSize);
				}
			}
		}
		
		if(lResult == ERROR_SUCCESS && pData != NULL)
		{
			bResult = PathRemoveFileSpec((LPTSTR)pData);
			strPath.Format(TEXT("%s"), (LPTSTR)pData);
		}
		else
		{
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
			if(dwSubKeys)
			{
				TCHAR szKeyName[MAX_KEY_LENGTH] = {0};
				DWORD dwKeyNameSize;
				for(DWORD i = 0; i < dwSubKeys; i++) 
				{ 
					dwKeyNameSize = MAX_KEY_LENGTH;
					lResult = RegEnumKeyEx(hKey, i,
						szKeyName, 
						&dwKeyNameSize, 
						NULL, 
						NULL, 
						NULL, 
						&ftLastWriteTime); 
					if (lResult == ERROR_SUCCESS) 
					{
						CString strEnumKeyName;
						strEnumKeyName.Format(TEXT("%s\\%s"), strSubKey, szKeyName);
						listRegistries.AddHead(strEnumKeyName);
					}
				}
			}
		}

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

		if(bResult)
			break;

	} while (!listRegistries.IsEmpty());

	return bResult;
}

BOOL CFirefoxPasswordRecovery::GetProfilePath(IPasswordRecoveryCallback* pCallback, CString& strPath)
{
	BOOL bResult = FALSE;

	do 
	{
		TCHAR szAppDataPath[MAX_PATH];
		if(!SUCCEEDED(SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, SHGFP_TYPE_CURRENT, szAppDataPath)))
			break;

		CString strAppDataFirefox;
		strAppDataFirefox.Format(TEXT("%s\\%s"), szAppDataPath, FILE_PATH_FIREFOX);
		if(!PathFileExists(strAppDataFirefox))
			break;

		CString strProfilePath;
		strProfilePath.Format(TEXT("%s\\%s"), strAppDataFirefox, FILE_PROFILE_FIREFOX);
		if(!PathFileExists(strProfilePath))
			break;

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
				int nIndex = strSectionName.Find(PROFILE_SECTION_PROFILE);
				if(nIndex >= 0)
				{
					TCHAR szProfilePath[MAX_PATH] = {0};
					dwResult = GetPrivateProfileString(strSectionName, PROFILE_KEY_PATH, 
						TEXT(""), szProfilePath, MAX_PATH, strProfilePath);

					strPath.Format(TEXT("%s\\%s"), strAppDataFirefox, szProfilePath);
					strPath.Replace(TEXT("/"), TEXT("\\"));
					if(PathFileExists(strPath))
					{
						bResult = TRUE;
						break;
					}
				}

				if(szSectionNames[i + 1] == 0)
					break;

				nPos = i + 1;
			}
		}
	} while (FALSE);

	return bResult;
}

BOOL CFirefoxPasswordRecovery::SetEnvironmentPath(IPasswordRecoveryCallback* pCallback, LPCTSTR lpszPath)
{
	BOOL bResult = FALSE;

	do 
	{
		TCHAR szEnvVariable[ENV_VARIABLE_LENGTH];
		if(GetEnvironmentVariableW(ENVIRONMENT_NAME_PATH, szEnvVariable, ENV_VARIABLE_LENGTH) == 0)
		{
			pCallback->OnRecoveryWarning(TEXT(""));
			break;
		}

		CString strEnvironmentPath;
		strEnvironmentPath.Format(TEXT("%s;%s"), szEnvVariable, lpszPath);
		bResult = SetEnvironmentVariable(ENVIRONMENT_NAME_PATH, strEnvironmentPath);
		
	} while (FALSE);

	return bResult;
}

/*
	#2c
	(list of domains for which passwords are never saved)
	.
	(site with a saved password)
	(name of HTML user name field or blank for HTTP authentication)
	(encrypted user name)
	*(name of HTML password field or blank for HTTP authentication)
	(encrypted password)
	.
	(more entries like the one above)
*/
void CFirefoxPasswordRecovery::ProcessVersionLess2_0(IPasswordRecoveryCallback* pCallback, LPCTSTR lpszPath)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	PCHAR pSignons = NULL;

	do 
	{
		hFile = CreateFile(lpszPath,
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
		pSignons = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
		if(pSignons == NULL)
			break;

		DWORD dwNumberOfBytesRead;
		if(!ReadFile(hFile, pSignons, dwFileSize, &dwNumberOfBytesRead, NULL))
			break;

		if(!boost::algorithm::starts_with(pSignons, SIGN_ON_VERSION_LESS_2))
			break;

		while((*(++pSignons)) != FULL_STOP_CHAR);

		std::vector<std::string> vecSignons;
		std::vector<std::string> vecEntries;
		boost::algorithm::split(vecSignons, pSignons, boost::is_any_of(FULL_STOP_STR), boost::token_compress_on);
		for(std::vector<std::string>::iterator it = vecSignons.begin(); it != vecSignons.end(); ++ it)
		{
			std::string strEntry = *it;
			boost::algorithm::split(vecEntries, strEntry, boost::is_any_of("\r\n"), boost::token_compress_on);
			if(vecEntries.size() < INDEX_PASSWORD)
				continue;

			int nIndex = 0;
			CString strSiteAddress;
			CString strLogin;
			CString strPassword;
			for(std::vector<std::string>::iterator it2 = vecEntries.begin(); it2 != vecEntries.end(); ++ it2)
			{
				std::string strLine = *it2;
				if(strLine.empty())
				{
					nIndex ++;
					continue;
				}

				if(nIndex == INDEX_SITE_ADDRESS && PathIsURLA(strLine.c_str()))
				{
#ifdef _UNICODE
					strSiteAddress.Format(TEXT("%s"), StringHelper::s2ws(strLine, CP_UTF8).c_str());
#else
					strSiteAddress.Format(TEXT("%s"), StringHelper::ws2s(StringHelper::s2ws(strLine, CP_UTF8), CP_ACP).c_str());
#endif
					RemoveLastPathSymbol(strSiteAddress);

					if(!MatchSiteAddress(strSiteAddress))
						break;
				}

				if(nIndex == INDEX_LOGIN && strLogin.IsEmpty())
				{
					if(!m_cPasswordDecryptor.Decrypt((PVOID)strLine.c_str(), strLine.length()))
						break;

					 if(!m_cPasswordDecryptor.GetDecryptString(strLogin))
						 break;
				}

				if(nIndex == INDEX_PASSWORD && strPassword.IsEmpty())
				{
					if(!m_cPasswordDecryptor.Decrypt((PVOID)strLine.c_str(), strLine.length()))
						break;

					if(!m_cPasswordDecryptor.GetDecryptString(strPassword))
						break;
				}

				nIndex ++;
			}

			if(!strSiteAddress.IsEmpty()
				&& !strLogin.IsEmpty()
				&& !strPassword.IsEmpty())
			{
				if(pCallback)
				{
					pCallback->OnRecoveryRecord(strSiteAddress, strLogin, strPassword, 0);
				}
				break;
			}
		}
	} while (FALSE);

	if(pSignons)
	{
		HeapFree(GetProcessHeap(), 0, pSignons);
		pSignons = NULL;
	}

	if(hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}
}

/*
	#2d
	(list of domains for which passwords are never saved)
	.
	(site with a saved password)
	(name of HTML user name field or blank for HTTP authentication)
	(encrypted user name)
	*(name of HTML password field or blank for HTTP authentication)
	(encrypted password)
	.
	(more entries like the one above)
*/
void CFirefoxPasswordRecovery::ProcessVersion2_0Between3_0(IPasswordRecoveryCallback* pCallback, LPCTSTR lpszPath)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	PCHAR pSignons = NULL;

	do 
	{
		hFile = CreateFile(lpszPath,
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
		pSignons = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
		if(pSignons == NULL)
			break;

		DWORD dwNumberOfBytesRead;
		if(!ReadFile(hFile, pSignons, dwFileSize, &dwNumberOfBytesRead, NULL))
			break;

		if(!boost::algorithm::starts_with(pSignons, SIGN_ON_VERSION_2_0BETWEEN3_0))
			break;

		while((*(++pSignons)) != FULL_STOP_CHAR);

		std::vector<std::string> vecSignons;
		std::vector<std::string> vecEntries;
		boost::algorithm::split(vecSignons, pSignons, boost::is_any_of(FULL_STOP_STR), boost::token_compress_on);
		for(std::vector<std::string>::iterator it = vecSignons.begin(); it != vecSignons.end(); ++ it)
		{
			std::string strEntry = *it;
			boost::algorithm::split(vecEntries, strEntry, boost::is_any_of("\r\n"), boost::token_compress_on);
			if(vecEntries.size() < INDEX_PASSWORD)
				continue;

			int nIndex = 0;
			CString strSiteAddress;
			CString strLogin;
			CString strPassword;
			for(std::vector<std::string>::iterator it2 = vecEntries.begin(); it2 != vecEntries.end(); ++ it2)
			{
				std::string strLine = *it2;
				if(strLine.empty())
				{
					nIndex ++;
					continue;
				}

				if(nIndex == INDEX_SITE_ADDRESS && PathIsURLA(strLine.c_str()))
				{
#ifdef _UNICODE
					strSiteAddress.Format(TEXT("%s"), StringHelper::s2ws(strLine, CP_UTF8).c_str());
#else
					strSiteAddress.Format(TEXT("%s"), StringHelper::ws2s(StringHelper::s2ws(strLine, CP_UTF8), CP_ACP).c_str());
#endif
					RemoveLastPathSymbol(strSiteAddress);

					if(!MatchSiteAddress(strSiteAddress))
						break;
				}

				if(nIndex == INDEX_LOGIN && strLogin.IsEmpty())
				{
					if(!m_cPasswordDecryptor.Decrypt((PVOID)strLine.c_str(), strLine.length()))
						break;

					if(!m_cPasswordDecryptor.GetDecryptString(strLogin))
						break;
				}

				if(nIndex == INDEX_PASSWORD && strPassword.IsEmpty())
				{
					if(!m_cPasswordDecryptor.Decrypt((PVOID)strLine.c_str(), strLine.length()))
						break;

					if(!m_cPasswordDecryptor.GetDecryptString(strPassword))
						break;
				}

				nIndex ++;
			}

			if(!strSiteAddress.IsEmpty()
				&& !strLogin.IsEmpty()
				&& !strPassword.IsEmpty())
			{
				if(pCallback)
				{
					pCallback->OnRecoveryRecord(strSiteAddress, strLogin, strPassword, 0);
				}
				break;
			}
		}
	} while (FALSE);

	if(pSignons)
	{
		HeapFree(GetProcessHeap(), 0, pSignons);
		pSignons = NULL;
	}

	if(hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}
}

/*
	#2e
	(list of domains for which passwords are never saved)
	.
	(site with a saved password)
	(name of HTML user name field or blank for HTTP authentication)
	(encrypted user name)
	*(name of HTML password field or blank for HTTP authentication)
	(encrypted password)
	(the domain of the log in form)
	(a filler line for future expansion, currently: '---')
	.
	(more entries like the one above)
*/
void CFirefoxPasswordRecovery::ProcessVersion3_0Between3_5(IPasswordRecoveryCallback* pCallback, LPCTSTR lpszPath)
{
	HANDLE hFile = INVALID_HANDLE_VALUE;
	PCHAR pSignons = NULL;

	do 
	{
		hFile = CreateFile(lpszPath,
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
		pSignons = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize);
		if(pSignons == NULL)
			break;

		DWORD dwNumberOfBytesRead;
		if(!ReadFile(hFile, pSignons, dwFileSize, &dwNumberOfBytesRead, NULL))
			break;

		if(!boost::algorithm::starts_with(pSignons, SIGN_ON_VERSION_3_0BETWEEN3_5))
			break;

		while((*(++pSignons)) != FULL_STOP_CHAR);

		std::vector<std::string> vecSignons;
		std::vector<std::string> vecEntries;
		boost::algorithm::split(vecSignons, pSignons, boost::is_any_of(FULL_STOP_STR), boost::token_compress_on);
		for(std::vector<std::string>::iterator it = vecSignons.begin(); it != vecSignons.end(); ++ it)
		{
			std::string strEntry = *it;
			boost::algorithm::split(vecEntries, strEntry, boost::is_any_of("\r\n"), boost::token_compress_on);
			if(vecEntries.size() < INDEX_PASSWORD)
				continue;

			int nIndex = 0;
			CString strSiteAddress;
			CString strLogin;
			CString strPassword;
			for(std::vector<std::string>::iterator it2 = vecEntries.begin(); it2 != vecEntries.end(); ++ it2)
			{
				std::string strLine = *it2;
				if(strLine.empty())
				{
					nIndex ++;
					continue;
				}

				if(boost::algorithm::equals(strLine, DASHED_LINE_STR))
					break;

				if(nIndex == INDEX_SITE_ADDRESS && PathIsURLA(strLine.c_str()))
				{
#ifdef _UNICODE
					strSiteAddress.Format(TEXT("%s"), StringHelper::s2ws(strLine, CP_UTF8).c_str());
#else
					strSiteAddress.Format(TEXT("%s"), StringHelper::ws2s(StringHelper::s2ws(strLine, CP_UTF8), CP_ACP).c_str());
#endif
					RemoveLastPathSymbol(strSiteAddress);

					if(!MatchSiteAddress(strSiteAddress))
						break;
				}

				if(nIndex == INDEX_LOGIN && strLogin.IsEmpty())
				{
					if(!m_cPasswordDecryptor.Decrypt((PVOID)strLine.c_str(), strLine.length()))
						break;

					if(!m_cPasswordDecryptor.GetDecryptString(strLogin))
						break;
				}

				if(nIndex == INDEX_PASSWORD && strPassword.IsEmpty())
				{
					if(!m_cPasswordDecryptor.Decrypt((PVOID)strLine.c_str(), strLine.length()))
						break;

					if(!m_cPasswordDecryptor.GetDecryptString(strPassword))
						break;
				}

				nIndex ++;
			}

			if(!strSiteAddress.IsEmpty()
				&& !strLogin.IsEmpty()
				&& !strPassword.IsEmpty())
			{
				if(pCallback)
				{
					pCallback->OnRecoveryRecord(strSiteAddress, strLogin, strPassword, 0);
				}
				break;
			}
		}
	} while (FALSE);

	if(pSignons)
	{
		HeapFree(GetProcessHeap(), 0, pSignons);
		pSignons = NULL;
	}

	if(hFile != INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}
}

void CFirefoxPasswordRecovery::ProcessVersion3_5Between32_0(IPasswordRecoveryCallback* pCallback, LPCTSTR lpszPath)
{
	sqlite3* pSqlite3;
#ifdef _UNICODE
	int rc = sqlite3_open(StringHelper::ws2s(lpszPath, CP_ACP).c_str(), &pSqlite3);
#else
	int rc = sqlite3_open(lpszPath, &pSqlite3);
#endif
	if(rc != SQLITE_OK)
	{
		CString strMessage;
		strMessage.Format(TEXT("Open File [%s] Error."), lpszPath);
		pCallback->OnRecoveryWarning(strMessage);
		return;
	}

	const char* pzTail;
	char* szSql = "SELECT hostname, encryptedUsername, encryptedPassword, encType FROM moz_logins;";
	sqlite3_stmt* pSqlite3Stmt;
	rc = sqlite3_prepare_v2(pSqlite3, szSql, -1, &pSqlite3Stmt, &pzTail);
	if(rc == SQLITE_OK)
	{
		while(sqlite3_step(pSqlite3Stmt) == SQLITE_ROW)
		{
			const unsigned char* szSiteAddress = sqlite3_column_text(pSqlite3Stmt, 0);
#ifdef _UNICODE
			CString strSiteAddress = StringHelper::s2ws((char*)szSiteAddress, CP_ACP).c_str();
#else
			CString strSiteAddress = szSiteAddress;
#endif
			RemoveLastPathSymbol(strSiteAddress);
			if(!MatchSiteAddress(strSiteAddress))
				continue;

			PCHAR szLogin = (PCHAR)sqlite3_column_text(pSqlite3Stmt, 1);
			int nLoginLength = sqlite3_column_bytes(pSqlite3Stmt, 1);
			if(!m_cPasswordDecryptor.Decrypt(szLogin, nLoginLength))
				continue;
			
			CString strLogin;
			if(!m_cPasswordDecryptor.GetDecryptString(strLogin))
				continue;

			PCHAR szPassword = (PCHAR)sqlite3_column_text(pSqlite3Stmt, 2);
			int nPasswordLength = sqlite3_column_bytes(pSqlite3Stmt, 2);
			if(!m_cPasswordDecryptor.Decrypt(szPassword, nPasswordLength))
				continue;

			CString strPassword;
			if(!m_cPasswordDecryptor.GetDecryptString(strPassword))
				continue;

			/* value 1 indicates encrypted */
			// long nEncType = sqlite3_column_int(pSqlite3Stmt, 3);	
			if(pCallback)
			{
#ifdef _UNICODE
				pCallback->OnRecoveryRecord(
					StringHelper::s2ws((char*)szSiteAddress, CP_ACP).c_str(),
					strLogin, 
					strPassword, 
					0);
#else
				pCallback->OnRecoveryRecord(
					szSiteAddress,
					strLogin, 
					strPassword, 
					0);
#endif
			}
		}
	}
	else
	{
#ifdef _UNICODE
		pCallback->OnRecoveryWarning(StringHelper::s2ws(pzTail, CP_ACP).c_str());
#else
		pCallback->OnRecoveryWarning(pzTail);
#endif
	}

	if(pSqlite3Stmt != NULL)
	{
		sqlite3_finalize(pSqlite3Stmt);
	}

	if(pSqlite3 != NULL)
	{
		sqlite3_close(pSqlite3);
	}
}

void CFirefoxPasswordRecovery::ProcessVersionAbove32_0(IPasswordRecoveryCallback* pCallback, LPCTSTR lpszPath)
{
	// Not Implement
}