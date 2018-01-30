#ifndef _PASSWORD_DECRYPTOR_H_
#define _PASSWORD_DECRYPTOR_H_

#pragma once
//////////////////////////////////////////////////////////////////////////
#include <wtypes.h>
#include <dpapi.h>
#include <shlwapi.h>
#include <shlobj.h>

// CPasswordDecryptor
//////////////////////////////////////////////////////////////////////////
class IPasswordDecryptor
{
public:
	virtual BOOL Decrypt(PVOID pCryptData, DWORD dwCryptDataSize, PVOID pOptionData, DWORD dwOptionDataSize) = 0;
};

class CPasswordDecryptor
	: public IPasswordDecryptor
{
public:
	CPasswordDecryptor();
	~CPasswordDecryptor();
public:
	BOOL GetHashString(PVOID pData, DWORD dwDataSize, CString &strHash);
	BOOL GetDecryptString(CString &strData);
	PVOID GetDecryptData(PDWORD pdwDataSize);
protected:
	VOID SetDecryptData(PVOID pData, DWORD dwDataSize);
	VOID FreeDecryptData();
protected:
	PVOID m_pDecryptData;
	DWORD m_dwDecryptDataSize;
};

// CChromePasswordDecryptor
//////////////////////////////////////////////////////////////////////////
class CChromePasswordDecryptor
	: public CPasswordDecryptor
{
public:
	virtual BOOL Decrypt(PVOID pCryptData, DWORD dwCryptDataSize, 
		PVOID pOptionData = NULL, DWORD dwOptionDataSize = 0);
};

class CFirefoxPasswordDecryptor
	: public CPasswordDecryptor
{
public:
	CFirefoxPasswordDecryptor();
	virtual ~CFirefoxPasswordDecryptor();
public:
	virtual BOOL Decrypt(PVOID pCryptData, DWORD dwCryptDataSize, 
		PVOID pOptionData = NULL, DWORD dwOptionDataSize = 0);
	virtual BOOL LoadDecryptModule(const CString& strModulePath, const CString& strProfilePath);
private:
	typedef enum SECDataType
	{
		siBuffer = 0,
		siClearDataBuffer = 1,
		siCipherDataBuffer,
		siDERCertBuffer,
		siEncodedCertBuffer,
		siDERNameBuffer,
		siEncodedNameBuffer,
		siAsciiNameString,
		siAsciiString,
		siDEROID,
		siUnsignedInteger,
		siUTCTime,
		siGeneralizedTime
	};

	struct SECData
	{
		SECDataType secDataType;
		PBYTE pbData;
		DWORD cbData;
	};

	typedef enum SECStatus
	{
		SECWouldBlock = -2,
		SECFailure = -1,
		SECSuccess = 0
	};

	typedef struct PK11SlotInfoStr PK11SlotInfo;
	typedef SECStatus(*NSS_Init) (const char*);
	typedef SECStatus(*NSS_Shutdown) (void);
	typedef PK11SlotInfo* (*PK11_GetInternalKeySlot) (void);
	typedef void(*PK11_FreeSlot) (PK11SlotInfo*);
	typedef SECStatus(*PK11_Authenticate) (PK11SlotInfo*, int, void*);
	typedef SECStatus(*PK11SDR_Decrypt) (SECData*, SECData*, void*);

	NSS_Init                m_pfpNSS_Init;
	NSS_Shutdown            m_pfnNSS_Shutdown;
	PK11_GetInternalKeySlot m_pfnPK11_GetInternalKeySlot;
	PK11_FreeSlot           m_pfnPK11_FreeSlot;
	PK11_Authenticate       m_pfnPK11_Authenticate;
	PK11SDR_Decrypt         m_pfnPK11SDR_Decrypt;

	HMODULE m_hModule;
	CString m_strModuleFile;
	CString m_strProfilePath;
};

// COperaPasswordDecryptor
//////////////////////////////////////////////////////////////////////////
class COperaPasswordDecryptor
	: public CPasswordDecryptor
{
public:
	virtual BOOL Decrypt(PVOID pCryptData, DWORD dwCryptDataSize, 
		PVOID pOptionData = NULL, DWORD dwOptionDataSize = 0);
};

// COperaPasswordDecryptor
//////////////////////////////////////////////////////////////////////////
class CInternetExplorerPasswordDecryptor
	: public CPasswordDecryptor
{
public:
	virtual BOOL Decrypt(PVOID pCryptData, DWORD dwCryptDataSize, 
		PVOID pOptionData = NULL, DWORD dwOptionDataSize = 0);
};

#endif // _PASSWORD_DECRYPTOR_H_