#pragma once

#ifndef __AFXWIN_H__
	#error "include 'stdafx.h' before including this file for PCH"
#endif

#include "resource.h"		// main symbols


// CFbPasswordRecoveryApp:
// See FbPasswordRecovery.cpp for the implementation of this class
class CFbPasswordRecoveryApp : public CWinApp
{
public:
	CFbPasswordRecoveryApp();

// Overrides
public:
	virtual BOOL InitInstance();

// Implementation

	DECLARE_MESSAGE_MAP()
};

extern CFbPasswordRecoveryApp theApp;