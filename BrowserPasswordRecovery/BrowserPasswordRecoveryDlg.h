#pragma once
//////////////////////////////////////////////////////////////////////////
#include "afxwin.h"
#include "PasswordRecovery.h"
#include "PasswordRecoveryManager.h"

#ifndef TEST
//#define TEST
#endif

// CFbPasswordRecoveryDlg
class CFbPasswordRecoveryDlg 
	: public CDialogEx
	, public IPasswordRecoveryCallback
{
public:
	CFbPasswordRecoveryDlg(CWnd* pParent = NULL);
public:
	enum { IDD = IDD_FBPASSWORDRECOVERY_DIALOG };
protected:
	virtual BOOL OnInitDialog();
	virtual void DoDataExchange(CDataExchange* pDX);
	virtual void OnRecoveryStart();
	virtual void OnRecoveryRecord(LPCTSTR lpszSiteAddress, LPCTSTR lpszLogin, LPCTSTR lpszPassword, LONG nDateCreated);
	virtual void OnRecoveryComplete();
	virtual void OnRecoveryWarning(LPCTSTR lpszMessage);
	virtual void OnRecoveryError(LPCTSTR lpszMessage);
protected:
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg void OnDestroy();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnBtnClickedRefresh();
	DECLARE_MESSAGE_MAP()
protected:
	static DWORD WINAPI ThreadRoutine_PasswordRecovery(LPVOID lpParameter);
public:
	void DoRecovery();
#ifdef TEST
	void DoTest();
#endif // TEST
private:
	void InitListCtrl();
private:
	HICON m_hIcon;
	CListCtrl m_cListCtrl;
	CStatic m_cTextMessage;
	CButton m_cBtnRefresh;
	
	CPasswordRecoveryManager* m_pPasswordRecoveryManager;			
};
