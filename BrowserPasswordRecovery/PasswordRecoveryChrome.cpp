#include "stdafx.h"
#include "Objbase.h"
#include "ShlObj.h"
#include "sqlite3/sqlite3.h"
#include "PasswordDecryptor.h"
#include "PasswordRecovery.h"

// CChromePasswordRecovery
//////////////////////////////////////////////////////////////////////////
#ifndef FILE_PATH_CHROME_WEB_DATA
#define FILE_PATH_CHROME_WEB_DATA TEXT("\\Google\\Chrome\\User Data\\Default\\Web Data")
#endif

#ifndef FILE_PATH_CHROME_LOGIN_DATA
#define FILE_PATH_CHROME_LOGIN_DATA TEXT("\\Google\\Chrome\\User Data\\Default\\Login Data")
#endif

void CChromePasswordRecovery::DoRecovery(IPasswordRecoveryCallback* pCallback)
{
#if 0
	// Chrome运行时无法打开Web Data和Login Data的文件
	if(IsChromeRunning())
	{
		pCallback->OnRecoveryWarning(TEXT("The program found that Google Chrome is running.\r\n\
			Please close Google Chrome and click OK to check passwords."));
		return;
	}

	CLSID clsid;
	HRESULT hr = CLSIDFromString(TEXT("{C91AF6FA-5F74-4423-9C89-86E897AC994A}"), &clsid);
	if(NOERROR != hr)
		return;
#endif

	TCHAR szPath[MAX_PATH];
	if(!SUCCEEDED(SHGetFolderPath(NULL, CSIDL_LOCAL_APPDATA, NULL, SHGFP_TYPE_CURRENT, szPath)))
	{
		pCallback->OnRecoveryWarning(TEXT("The program can't found Google Chrome appdata directory."));
		return;
	}

	// %AppData%\\Google\\Chrome\\User Data\\Default\\Web Data
	{
		TCHAR szWebDataPath[MAX_PATH] = {0};
		lstrcpy(szWebDataPath, szPath);
		PathAppend(szWebDataPath, FILE_PATH_CHROME_WEB_DATA);
		if(PathFileExists(szWebDataPath))
		{
			ProcessData(pCallback, szWebDataPath);
		}
	}

	// %AppData%\\Google\\Chrome\\User Data\\Default\\Login Data
	{
		TCHAR szLoginDataPath[MAX_PATH] = {0};
		lstrcpy(szLoginDataPath, szPath);
		PathAppend(szLoginDataPath, FILE_PATH_CHROME_LOGIN_DATA);
		if(PathFileExists(szLoginDataPath))
		{
			ProcessData(pCallback, szLoginDataPath);
		}
	}
}

BOOL CChromePasswordRecovery::IsChromeRunning()
{
	return FindWindow(TEXT("Chrome_WidgetWin_0"), NULL) != NULL;
}

void CChromePasswordRecovery::ProcessData(IPasswordRecoveryCallback* pCallback, LPCTSTR lpszPath)
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
	char* szSql = "SELECT signon_realm, username_value, password_value, date_created FROM logins;";
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

			const unsigned char* szLogin = sqlite3_column_text(pSqlite3Stmt, 1);
			PBYTE szPassword = (PBYTE)sqlite3_column_blob(pSqlite3Stmt, 2);
			int nPasswordLength = sqlite3_column_bytes(pSqlite3Stmt, 2);
			long nDateCreated = sqlite3_column_int(pSqlite3Stmt, 3);

			if(!m_cPasswordDecryptor.Decrypt(szPassword, nPasswordLength))
				continue;
			
			CString strPassword;
			if(!m_cPasswordDecryptor.GetDecryptString(strPassword))
				continue;

			if(pCallback)
			{
#ifdef _UNICODE
				pCallback->OnRecoveryRecord(
					strSiteAddress,
					StringHelper::s2ws((char*)szLogin, CP_ACP).c_str(), 
					strPassword, 
					nDateCreated);
#else
				pCallback->OnRecoveryRecord(
					strSiteAddress,
					szLogin, 
					strPassword, 
					nDateCreated);
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