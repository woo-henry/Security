#include "stdafx.h"
#include "PasswordRecords.h"

// CPasswordRecordItem
//////////////////////////////////////////////////////////////////////////
class CPasswordRecord
{
public:
	CPasswordRecord(LPCTSTR lpszSiteAddress, LPCTSTR lpszLogin, LPCTSTR lpszPassword, LONG nDateCreated)
		: m_strSiteAddress(lpszSiteAddress)
		, m_strLogin(lpszLogin)
		, m_strPassword(lpszPassword)
		, m_nDateCreated(nDateCreated)
	{

	}
public:
	const CString& GetSiteAddress() const
	{
		return m_strSiteAddress;
	}
	const CString& GetLogin() const
	{
		return m_strLogin;
	}
	const CString& GetPassword() const
	{
		return m_strPassword;
	}
	LONG GetDateCreated() const
	{
		return m_nDateCreated;
	}
private:
	CString m_strSiteAddress;
	CString m_strLogin;
	CString m_strPassword;
	LONG	m_nDateCreated;
};

// CPasswordRecords
//////////////////////////////////////////////////////////////////////////
CPasswordRecords::CPasswordRecords()
{

}
 
CPasswordRecords::~CPasswordRecords()
{
	if(m_cItems.IsEmpty())
		return;

	POSITION pos;  
	for(pos = m_cItems.GetHeadPosition(); pos != NULL;)
	{  
		CPasswordRecord* pItem = (CPasswordRecord*)m_cItems.GetNext(pos);  
		if(pItem != NULL)
		{
			delete pItem;
			pItem = NULL;
		}
	}

	m_cItems.RemoveAll();
}

void CPasswordRecords::Add(LPCTSTR lpszSiteAddress, LPCTSTR lpszLogin, LPCTSTR lpszPassword, LONG nDateCreated)
{
	m_cItems.AddHead(new CPasswordRecord(lpszSiteAddress, lpszLogin, lpszPassword, nDateCreated));
}