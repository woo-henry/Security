#ifndef _SECRET_H_
#define _SECRET_H_

#pragma once
//////////////////////////////////////////////////////////////////////////
#include <wtypes.h>

typedef struct tagSecretEntry
{
	DWORD Offset;
	BYTE  SecretId[8];
	DWORD Length;
}SecretEntry, *PSecretEntry;

typedef struct tagSecretInfoHeader
{
	DWORD IdHeader;
	DWORD Size;
	DWORD TotalSecrets;
	DWORD Unknown;
	DWORD Id4;
	DWORD UnknownZero;
}SecretInfoHeader, *PSecretInfoHeader;

typedef struct tagAutoComplteSecretHeader
{
	DWORD Size;
	DWORD SecretInfoSize;
	DWORD SecretSize;
	SecretInfoHeader SecretHeader;
	//SecretEntry SecretEntries[numSecrets];
	//WCHAR Secrets[numSecrets];
}AutoComplteSecretHeader, *PAutoComplteSecretHeader;

#endif // _SECRET_H_