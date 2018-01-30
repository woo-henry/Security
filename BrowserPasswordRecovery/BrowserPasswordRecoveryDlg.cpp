// FbPasswordRecoveryDlg.cpp : implementation file
//

#include "stdafx.h"
#include "afxdialogex.h"
#include "BrowserPasswordRecoveryApp.h"
#include "BrowserPasswordRecoveryDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// CAboutDlg dialog used for App About
class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() 
	: CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CFbPasswordRecoveryDlg dialog
CFbPasswordRecoveryDlg::CFbPasswordRecoveryDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CFbPasswordRecoveryDlg::IDD, pParent)
	, m_pPasswordRecoveryManager(new CPasswordRecoveryManager(this))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

BEGIN_MESSAGE_MAP(CFbPasswordRecoveryDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BTN_REFRESH, &CFbPasswordRecoveryDlg::OnBtnClickedRefresh)
	ON_WM_DESTROY()
END_MESSAGE_MAP()

// CFbPasswordRecoveryDlg message handlers
BOOL CFbPasswordRecoveryDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	InitListCtrl();

	return TRUE;
}

void CFbPasswordRecoveryDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_RECORD, m_cListCtrl);
	DDX_Control(pDX, IDC_TEXT_MESSAGE, m_cTextMessage);
	DDX_Control(pDX, IDC_BTN_REFRESH, m_cBtnRefresh);
}

void CFbPasswordRecoveryDlg::OnRecoveryStart()
{
	m_cListCtrl.DeleteAllItems();

	m_cBtnRefresh.EnableWindow(FALSE);

	m_cTextMessage.SetWindowText(TEXT("Recovery Passwords Start."));
}

void CFbPasswordRecoveryDlg::OnRecoveryRecord(LPCTSTR lpszSiteAddress, LPCTSTR lpszLogin, LPCTSTR lpszPassword, LONG nDateCreated)
{
	int nItem = m_cListCtrl.InsertItem(0, lpszSiteAddress);
	m_cListCtrl.SetItemText(nItem, 1, lpszLogin);
	m_cListCtrl.SetItemText(nItem, 2, lpszPassword);

	int nCount = m_cListCtrl.GetItemCount();
	CString strMessage;
	strMessage.Format(TEXT("Recovery Passwords Record : %d ."), nCount);
	m_cTextMessage.SetWindowText(strMessage);
}

void CFbPasswordRecoveryDlg::OnRecoveryComplete()
{
	m_cTextMessage.SetWindowText(TEXT("Recovery Passwords Complete."));

	m_cBtnRefresh.EnableWindow(TRUE);
}

void CFbPasswordRecoveryDlg::OnRecoveryWarning(LPCTSTR lpszMessage)
{
	m_cTextMessage.SetWindowText(lpszMessage);
}

void CFbPasswordRecoveryDlg::OnRecoveryError(LPCTSTR lpszMessage)
{
	m_cTextMessage.SetWindowText(lpszMessage);
}

void CFbPasswordRecoveryDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

void CFbPasswordRecoveryDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this);

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

void CFbPasswordRecoveryDlg::OnDestroy()
{
	if(m_pPasswordRecoveryManager)
	{
		delete m_pPasswordRecoveryManager;
		m_pPasswordRecoveryManager = NULL;
	}

	__super::OnDestroy();
}

HCURSOR CFbPasswordRecoveryDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CFbPasswordRecoveryDlg::OnBtnClickedRefresh()
{
	DWORD dwThreadId;
	HANDLE hThread = CreateThread(NULL, 0, ThreadRoutine_PasswordRecovery, this, 0, &dwThreadId);
	if(hThread)
	{
		CloseHandle(hThread);
	}
}

void CFbPasswordRecoveryDlg::DoRecovery()
{
#ifdef TEST
	DoTest();
#else
	m_pPasswordRecoveryManager->DoRecovery();
#endif // TEST
}

#ifdef TEST
BOOL GetUrlHash(CString strUrl, CString &strResult)
{
	BOOL bResult = FALSE;
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;

	strUrl.MakeLower();
	if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) 
	{
		if (CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
		{
			if (CryptHashData(hHash, (PBYTE)strUrl.GetBuffer(0), strUrl.GetLength() * sizeof(TCHAR) + 2, 0))
			{
				strUrl.ReleaseBuffer();

				BYTE bHash[20];
				DWORD dwHashLen = sizeof(bHash);
				if ((bResult = CryptGetHashParam(hHash, HP_HASHVAL, bHash, &dwHashLen, 0)))
				{
					BYTE chksum = 0;
					wchar_t ch[4];
					for (size_t i = 0;i < 20 + 1;i++) 
					{
						BYTE x;
						if (i < 20) 
						{
							x = bHash[i];
							chksum += x;
						} 
						else 
						{
							x = chksum;
						}
						wsprintf(ch, L"%02X", x);
						strResult.AppendChar(ch[0]);
						strResult.AppendChar(ch[1]);
					}
				}
			}
			CryptDestroyHash(hHash);      
		}
		CryptReleaseContext(hProv, 0);
	}
	return bResult;
}

void CFbPasswordRecoveryDlg::DoTest()
{
	CString strURL(TEXT("https://www.facebook.com/"));
	CString strHash;
	GetUrlHash(strURL, strHash);
	if(strHash == TEXT("EF44D3E034009CB0FD1B1D81A1FF3F3335213BD796"))
	{
		m_cTextMessage.SetWindowText(strHash);
	}
}
#endif // TEST

void CFbPasswordRecoveryDlg::InitListCtrl()
{
	CRect rcClient;
	m_cListCtrl.GetClientRect(rcClient);
	int nColumnWidth = rcClient.Width() / 4;

	DWORD dwExtendedStyle = m_cListCtrl.GetExtendedStyle();
	m_cListCtrl.SetExtendedStyle( dwExtendedStyle | LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);
	m_cListCtrl.InsertColumn(0, TEXT("Site address"), LVCFMT_CENTER, nColumnWidth * 2);
	m_cListCtrl.InsertColumn(1, TEXT("Login"), LVCFMT_CENTER, nColumnWidth);
	m_cListCtrl.InsertColumn(2, TEXT("Password"), LVCFMT_CENTER, nColumnWidth);
}

DWORD WINAPI CFbPasswordRecoveryDlg::ThreadRoutine_PasswordRecovery(LPVOID lpParameter)
{
	CFbPasswordRecoveryDlg* pDlg = (CFbPasswordRecoveryDlg*)lpParameter;
	if(pDlg == NULL)
		return EXIT_FAILURE;

	pDlg->DoRecovery();
	
	return EXIT_SUCCESS;
}
