#include "stdafx.h"
#include "PasswordDecryptor.h"

//////////////////////////////////////////////////////////////////////////
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "shlwapi.lib")
#pragma comment (lib, "shell32.lib")

// CPasswordDecryptor
//////////////////////////////////////////////////////////////////////////
CPasswordDecryptor::CPasswordDecryptor()
	: m_pDecryptData(NULL)
	, m_dwDecryptDataSize(0)
{

}

CPasswordDecryptor::~CPasswordDecryptor()
{
	FreeDecryptData();
}

BOOL CPasswordDecryptor::GetHashString(PVOID pData, DWORD dwDataSize, CString &strHash)
{
	BOOL bResult = FALSE;
	HCRYPTPROV hProv = NULL;
	HCRYPTHASH hHash = NULL;

	do 
	{
		if(!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
			break;

		if(!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
			break;

		if(!CryptHashData(hHash, (PBYTE)pData, dwDataSize, 0))
			break;

		BYTE pBuffer[20];
		DWORD dwBufferSize = sizeof(pBuffer);
		if((bResult = CryptGetHashParam(hHash, HP_HASHVAL, pBuffer, &dwBufferSize, 0)))
		{
			BYTE chksum = 0;
			TCHAR ch[4];
			for (int i = 0; i < 20 + 1; i++) 
			{
				BYTE x;
				if (i < 20)
				{
					x = pBuffer[i];
					chksum += x;
				} 
				else
				{
					x = chksum;
				}
				
				_stprintf_s(ch, TEXT("%02X"), x);

				strHash.AppendChar(ch[0]);
				strHash.AppendChar(ch[1]);
			}
		}
	} while (FALSE);

	if(hHash != NULL)
	{
		CryptDestroyHash(hHash);
		hHash = NULL;
	}

	if(hProv != NULL)
	{
		CryptReleaseContext(hProv, 0);
		hProv = NULL;
	}	

	return bResult;
}

BOOL CPasswordDecryptor::GetDecryptString(CString &strData)
{
	if(m_pDecryptData == NULL)
		return FALSE;

	if(m_dwDecryptDataSize == 0)
		return FALSE;

#ifdef _UNICODE
	strData.Format(TEXT("%s"), StringHelper::s2ws((PCHAR)m_pDecryptData, CP_ACP).c_str());
#else
	strData.Format(TEXT("%s"), (PCHAR)m_pDecryptData);
#endif
	
	return TRUE;
}

PVOID CPasswordDecryptor::GetDecryptData(PDWORD pdwDataSize)
{
	if(pdwDataSize)
	{
		*pdwDataSize = m_dwDecryptDataSize;
	}

	return m_pDecryptData;
}

VOID CPasswordDecryptor::SetDecryptData(PVOID pData, DWORD dwDataSize)
{
	FreeDecryptData();

	m_pDecryptData = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwDataSize);
	if(m_pDecryptData)
	{
		RtlCopyMemory(m_pDecryptData, pData, dwDataSize);

		m_dwDecryptDataSize = dwDataSize;
	}
}

VOID CPasswordDecryptor::FreeDecryptData()
{
	if(m_pDecryptData)
	{
		HeapFree(GetProcessHeap(), 0, m_pDecryptData);
		m_pDecryptData = NULL;
	}

	m_dwDecryptDataSize = 0;
}

// CChromePasswordDecryptor
//////////////////////////////////////////////////////////////////////////
BOOL CChromePasswordDecryptor::Decrypt(PVOID pCryptData, DWORD dwCryptDataSize, 
									   PVOID pOptionalData, DWORD dwOptionalDataSize)
{
	UNREFERENCED_PARAMETER(pOptionalData);
	UNREFERENCED_PARAMETER(dwOptionalDataSize);

	BOOL bResult = TRUE;
	DATA_BLOB DataIn;
	DATA_BLOB DataOut;
	LPWSTR pszDataDescr = NULL;

	do 
	{
		DataIn.pbData = (PBYTE)pCryptData;
		DataIn.cbData = dwCryptDataSize;
		if (!CryptUnprotectData(
			&DataIn,
			&pszDataDescr,
			NULL,
			NULL,
			NULL,
			0,
			&DataOut))
		{
			bResult = FALSE;
			break;
		}

		if(DataOut.cbData == 0)
		{
			bResult = FALSE;
			break;
		}

		SetDecryptData(DataOut.pbData, DataOut.cbData);

	} while (FALSE);

	if(DataOut.pbData)
	{
		LocalFree(DataOut.pbData);
	}

	return bResult;
}

// CFirefoxPasswordDecryptor
//////////////////////////////////////////////////////////////////////////
CFirefoxPasswordDecryptor::CFirefoxPasswordDecryptor()
	: m_hModule(NULL)
	, m_pfpNSS_Init(NULL)
	, m_pfnNSS_Shutdown(NULL)
	, m_pfnPK11_GetInternalKeySlot(NULL)
	, m_pfnPK11_FreeSlot(NULL)
	, m_pfnPK11_Authenticate(NULL)
	, m_pfnPK11SDR_Decrypt(NULL)
{

}

CFirefoxPasswordDecryptor::~CFirefoxPasswordDecryptor()
{
	m_pfpNSS_Init = NULL;
	m_pfnNSS_Shutdown = NULL;
	m_pfnPK11_GetInternalKeySlot = NULL;
	m_pfnPK11_FreeSlot = NULL;
	m_pfnPK11_Authenticate = NULL;
	m_pfnPK11SDR_Decrypt = NULL;

	if(m_hModule)
	{
		FreeLibrary(m_hModule);
		m_hModule = NULL;
	}
}

BOOL CFirefoxPasswordDecryptor::Decrypt(PVOID pCryptData, DWORD dwCryptDataSize, 
										PVOID pOptionalData, DWORD dwOptionalDataSize)
{
	UNREFERENCED_PARAMETER(pOptionalData);
	UNREFERENCED_PARAMETER(dwOptionalDataSize);

	BOOL bResult = TRUE;
	BOOL bInit = FALSE;
	PK11SlotInfo* pSlotInfo = NULL;
	SECStatus secStatus = SECFailure;
	SECData DataIn, DataOut;

	do 
	{
		if(m_pfpNSS_Init)
		{
			secStatus = (*m_pfpNSS_Init)((LPCSTR)StringHelper::ws2s((LPCTSTR)m_strProfilePath, CP_ACP).c_str());
			if (secStatus != SECSuccess)
			{
				bResult = FALSE;
				break;
			}
			else
			{
				bInit = TRUE;
			}
		}

		PK11SlotInfo* pSlotInfo = (*m_pfnPK11_GetInternalKeySlot)();
		if(pSlotInfo == NULL)
		{
			bResult = FALSE;
			break;
		}

		SECStatus secStatus = (*m_pfnPK11_Authenticate)(pSlotInfo, TRUE, NULL);
		if (secStatus != SECSuccess)
		{
			bResult = FALSE;
			break;
		}

		DataIn.pbData = (PBYTE)pCryptData;
		DataIn.cbData = dwCryptDataSize;
		DataOut.pbData = NULL;
		DataOut.cbData = 0;
		secStatus = (*m_pfnPK11SDR_Decrypt)(&DataIn, &DataOut, NULL);
		if (secStatus != SECSuccess || DataOut.cbData == 0)
		{
			bResult = FALSE;
			break;
		}
		
		SetDecryptData(DataOut.pbData, DataOut.cbData);

	} while (FALSE);

	if(DataOut.pbData)
	{
		LocalFree(DataOut.pbData);
	}

	if(m_pfnPK11_FreeSlot && pSlotInfo)
	{
		(*m_pfnPK11_FreeSlot)(pSlotInfo);
	}

	if(bInit && m_pfnNSS_Shutdown)
	{
		(*m_pfnNSS_Shutdown)();
	}
	
	return bResult;
}

BOOL CFirefoxPasswordDecryptor::LoadDecryptModule(const CString& strModulePath, const CString& strProfilePath)
{
	if(m_hModule != NULL 
		&& m_pfpNSS_Init != NULL
		&& m_pfnNSS_Shutdown != NULL
		&& m_pfnPK11_GetInternalKeySlot != NULL
		&& m_pfnPK11_FreeSlot != NULL
		&& m_pfnPK11_Authenticate != NULL
		&& m_pfnPK11SDR_Decrypt != NULL)
		return TRUE;

	m_strModuleFile.Format(TEXT("%s\\%s"), strModulePath, TEXT("nss3.dll"));
	if(!PathFileExists(m_strModuleFile))
		return FALSE;

	m_strProfilePath.Format(TEXT("%s"), strProfilePath);
	if(!PathFileExists(m_strModuleFile))
		return FALSE;

	m_hModule = LoadLibrary(m_strModuleFile);
	if(m_hModule == NULL)
		return FALSE;

	m_pfpNSS_Init = (NSS_Init)GetProcAddress(m_hModule, "NSS_Init");
	if(m_pfpNSS_Init == NULL)
		return FALSE;

	m_pfnNSS_Shutdown = (NSS_Shutdown)GetProcAddress(m_hModule, "NSS_Shutdown");
	if(m_pfnNSS_Shutdown == NULL)
		return FALSE;

	m_pfnPK11_GetInternalKeySlot = (PK11_GetInternalKeySlot)GetProcAddress(m_hModule, "PK11_GetInternalKeySlot");
	if(m_pfnPK11_GetInternalKeySlot == NULL)
		return FALSE;

	m_pfnPK11_FreeSlot = (PK11_FreeSlot)GetProcAddress(m_hModule, "PK11_FreeSlot");
	if(m_pfnPK11_FreeSlot == NULL)
		return FALSE;

	m_pfnPK11_Authenticate = (PK11_Authenticate)GetProcAddress(m_hModule, "PK11_Authenticate");
	if(m_pfnPK11_Authenticate == NULL)
		return FALSE;

	m_pfnPK11SDR_Decrypt = (PK11SDR_Decrypt)GetProcAddress(m_hModule, "PK11SDR_Decrypt");
	if(m_pfnPK11SDR_Decrypt == NULL)
		return FALSE;

	return TRUE;
}

// COperaPasswordDecryptor
//////////////////////////////////////////////////////////////////////////
BOOL COperaPasswordDecryptor::Decrypt(PVOID pCryptData, DWORD dwCryptDataSize, 
									  PVOID pOptionalData, DWORD dwOptionalDataSize)
{
	BOOL bResult = FALSE;

	return bResult;
}

// CInternetExplorerPasswordDecryptor
//////////////////////////////////////////////////////////////////////////
BOOL CInternetExplorerPasswordDecryptor::Decrypt(PVOID pCryptData, DWORD dwCryptDataSize, 
												 PVOID pOptionalData, DWORD dwOptionalDataSize)
{
	BOOL bResult = TRUE;
	DATA_BLOB DataIn;
	DATA_BLOB DataOut;
	DATA_BLOB DataOptional;
	LPWSTR pszDataDescr = NULL;

	do 
	{
		DataIn.pbData = (PBYTE)pCryptData;
		DataIn.cbData = dwCryptDataSize;
		DataOptional.pbData = (PUCHAR)pOptionalData;
		DataOptional.cbData = dwOptionalDataSize; 

		if (!CryptUnprotectData(
			&DataIn,
			&pszDataDescr,
			&DataOptional,
			NULL,
			NULL,
			0,
			&DataOut))
		{
			bResult = FALSE;
			break;
		}

		if(DataOut.pbData == NULL || DataOut.cbData == 0)
		{
			bResult = FALSE;
			break;
		}

		SetDecryptData(DataOut.pbData, DataOut.cbData);

	} while (FALSE);

	if(DataOut.pbData)
	{
		LocalFree(DataOut.pbData);
	}

	return bResult;
}