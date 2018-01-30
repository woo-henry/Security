#include "stdafx.h"
#include "StringHelper.h"

// StringHelper
//////////////////////////////////////////////////////////////////////////
VOID StringHelper::s2ws(LPCSTR lpszSource, LPWSTR lpszDest, UINT uiCodePage)
{
	DWORD dwCount = MultiByteToWideChar(uiCodePage, 0, lpszSource, -1, NULL, 0); 
	LPVOID lpDestBuf = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwCount * sizeof(WCHAR));
	if(lpDestBuf)
	{
		MultiByteToWideChar(uiCodePage, 0, lpszSource, -1, (LPWSTR)lpDestBuf, dwCount); 
		lstrcpyW(lpszDest, (LPWSTR)lpDestBuf);
		HeapFree(GetProcessHeap(), 0, lpDestBuf);
	}
}

VOID StringHelper::ws2s(LPCWSTR lpszSource, LPSTR lpszDest, UINT uiCodePage)
{
	DWORD dwCount = WideCharToMultiByte(uiCodePage, 0, lpszSource, -1, NULL, 0, NULL, NULL);
	LPVOID lpDestBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwCount + 1);
	if(lpDestBuf)
	{
		WideCharToMultiByte(uiCodePage, 0, lpszSource, -1, (LPSTR)lpDestBuf, dwCount, NULL, NULL);
		lstrcpyA(lpszDest, (LPSTR)lpDestBuf);
		HeapFree(GetProcessHeap(), 0, lpDestBuf);
	}
}

std::wstring StringHelper::s2ws(const std::string &strSource, UINT iCodePage)
{
	std::wstring strDest;

	DWORD dwCount = MultiByteToWideChar(iCodePage, 0, strSource.c_str(), -1, nullptr, 0);
	LPWSTR lpDestBuf = (LPWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwCount * sizeof(WCHAR));
	if(lpDestBuf)
	{
		MultiByteToWideChar(iCodePage, 0, strSource.c_str(), -1, lpDestBuf, dwCount);
		strDest = lpDestBuf;
		HeapFree(GetProcessHeap(), 0, lpDestBuf);
	}
	
	return strDest;
}

std::string StringHelper::ws2s(const std::wstring &strSource, UINT iCodePage)
{
	std::string strDest;

	DWORD dwCount = WideCharToMultiByte(iCodePage, 0, strSource.c_str(), -1, nullptr, 0, nullptr, nullptr);
	LPSTR lpDestBuf = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwCount * sizeof(CHAR));
	if(lpDestBuf)
	{
		WideCharToMultiByte(iCodePage, 0, strSource.c_str(), -1, lpDestBuf, dwCount, nullptr, nullptr);
		strDest = lpDestBuf;
		HeapFree(GetProcessHeap(), 0, lpDestBuf);
	}

	return strDest;
}