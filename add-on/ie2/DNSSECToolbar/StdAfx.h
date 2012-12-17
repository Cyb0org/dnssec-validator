// stdafx.h : include file for standard system include files,
//      or project specific include files that are used frequently,
//      but are changed infrequently

//#define _AFXDLL
//#define _AFXEXT


#if !defined(AFX_STDAFX_H__A68061D7_9C5C_4243_B0B1_2A6ACBD51547__INCLUDED_)
#define AFX_STDAFX_H__A68061D7_9C5C_4243_B0B1_2A6ACBD51547__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define STRICT
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#define _ATL_APARTMENT_THREADED

//#include <afxwin.h>
#include <afxdisp.h>
#include <afxcmn.h>

//#include <atlbase.h>
//You may derive a class from CComModule and use it if you want to override
//something, but do not change the name of _Module
extern CComModule _Module;
//#include <atlcom.h>
//#include <atlconv.h>
//#include <afxconv.h>
//#include <shlobj.h>
//#include <shlwapi.h>
#include <atlctl.h>
//#include <atltrace.h>
#include <comdef.h>

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.
using namespace ATL;

#endif // !defined(AFX_STDAFX_H__A68061D7_9C5C_4243_B0B1_2A6ACBD51547__INCLUDED)
