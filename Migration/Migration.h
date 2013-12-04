#pragma once

#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' " "version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#pragma comment(lib,"comctl32.lib")

typedef VOID(WINAPI *GNSITYPE)(LPSYSTEM_INFO lpSystemInfo);

