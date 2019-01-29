#ifndef _STDAFX_H_
#define _STDAFX_H_

// ATL Í·ÎÄ¼þ:
#include <atlbase.h>
#include <atlstr.h>

extern CComModule _Module;

#include <atlwin.h>
#include <atlfile.h>
#include <atlcoll.h>
#include <atlenc.h>

#include <Commdlg.h>
#include <Windowsx.h>
#include <Imagehlp.h>
#pragma comment(lib, "WS2_32.lib")      // some symbol are used in OpenSSL static lib
#pragma comment(lib, "Crypt32.lib")     // some symbol are used in OpenSSL static lib
#pragma comment(lib, "version.lib") 
#pragma comment(lib, "Imagehlp.lib") 

// OpenSSL 1.0.2 precompiled lib, download from http://slproweb.com/products/Win32OpenSSL.html,
// direct link http://slproweb.com/download/Win32OpenSSL-1_0_2q.exe

// Capstone disassembly/disassembler framework, download from https://github.com/aquynh/capstone/releases,

#define KEY_BIT 2048

#define HR_CHECK(_hr_) hr = _hr_; if (FAILED(hr)) { goto exit; }
#define BOOL_CHECK(_hr_) if (!(_hr_)) { hr = HRESULT_FROM_WIN32(::GetLastError()); goto exit; }

#include "Resource.h"

#endif // _STDAFX_H_