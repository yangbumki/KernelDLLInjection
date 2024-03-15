#pragma once
#include <Windows.h>
#include <iostream>

typedef class PRIVILEGE {
private:
	HANDLE tokenHandle = NULL;
	LUID luid;
	TOKEN_PRIVILEGES tp = { 0, };

	void ErrorMessage(const char* msg) {
		MessageBoxA(NULL, msg, "ERROR", NULL);
		exit(1);
	};

public:
	PRIVILEGE(HANDLE token) {
		tokenHandle = token;
	};

	BOOL SetPrivilege(const wchar_t* mode, BOOL enable) {
		if (!LookupPrivilegeValue(NULL, mode, &luid)) {
			printf_s("LookupPrivilegeValueA \n");
			return FALSE;
		}

		this->tp.PrivilegeCount = 1;
		this->tp.Privileges[0].Luid = luid;

		if (enable) 
			this->tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		else
			tp.Privileges[0].Attributes = 0;

		if (!AdjustTokenPrivileges(tokenHandle, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
			printf_s("AdjustTokenPrivileges \n");
			return FALSE;
		};


		return TRUE;
	};
}privilege;

