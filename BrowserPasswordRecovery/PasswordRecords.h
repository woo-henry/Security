#ifndef _PASSWORD_RECORDS_H_
#define _PASSWORD_RECORDS_H_

#pragma once
//////////////////////////////////////////////////////////////////////////
class CPasswordRecords
{
public:
	CPasswordRecords();
	virtual ~CPasswordRecords();
public:
	void Add(LPCTSTR lpszSiteAddress, LPCTSTR lpszLogin, LPCTSTR lpszPassword, LONG nDateCreated);
private:
	CPtrList m_cItems;
};

#endif // _PASSWORD_RECORDS_H_