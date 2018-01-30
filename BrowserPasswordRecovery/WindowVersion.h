#ifndef _WINDOWS_VERSION_H_
#define _WINDOWS_VERSION_H_

#pragma once
//////////////////////////////////////////////////////////////////////////
#ifndef IS_WINDOWS_7
#define IS_WINDOWS_7(v)					(LOBYTE(LOWORD((v))) == 6 && HIBYTE(LOWORD((v))) == 1)
#endif

#ifndef IS_LESS_THAN_WINDOWS_7
#define IS_LESS_THAN_WINDOWS_7(v)		(LOBYTE(LOWORD((v))) * 10 + HIBYTE(LOWORD((v))) <= 61)
#endif

#ifndef IS_WINDOWS_8
#define IS_WINDOWS_8(v)					(LOBYTE(LOWORD((v))) == 6 && HIBYTE(LOWORD((v))) == 2)
#endif

#ifndef IS_GREATER_WINDOWS_8
#define IS_GREATER_WINDOWS_8(v)			(LOBYTE(LOWORD((v))) == 6 && HIBYTE(LOWORD((v))) >= 2)
#endif

#ifndef IS_WINDOWS_8_1
#define IS_WINDOWS_8_1(v)				(LOBYTE(LOWORD((v))) == 6 && HIBYTE(LOWORD((v))) == 3)
#endif

#ifndef IS_GREATER_WINDOWS_8_1
#define IS_GREATER_WINDOWS_8_1(v)		(LOBYTE(LOWORD((v))) == 6 && HIBYTE(LOWORD((v))) >= 3)
#endif

#ifndef IS_WINDOWS_10
#define IS_WINDOWS_10(v)				(LOBYTE(LOWORD((v))) == 10 && HIBYTE(LOWORD((v))) == 0)
#endif

#ifndef IE_VERSION_6
#define IE_VERSION_6					6
#endif

#endif // _WINDOWS_VERSION_H_