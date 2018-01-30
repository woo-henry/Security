#ifndef _STRING_HELPER_H_
#define _STRING_HELPER_H_

#pragma once
//////////////////////////////////////////////////////////////////////////
#include <wtypes.h>
#include <string>

class StringHelper
{
public:
	static VOID s2ws(LPCSTR lpszSource, LPWSTR lpszDest, UINT uiCodePage);
	static VOID ws2s(LPCWSTR lpszSource, LPSTR lpszDest, UINT uiCodePage);
	static std::wstring s2ws(const std::string &strSource, UINT uiCodePage);
	static std::string ws2s(const std::wstring &strSource, UINT uiCodePage);
};

#endif // _STRING_HELPER_H_