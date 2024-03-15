#include <iostream>
#include <Windows.h>

#include "Privilege.hpp"
#include "Injector.hpp"

using namespace std;

int main() {
	HANDLE tokenHandle = NULL;
	DWORD pid = 0;
	INJECTOR ij;
	wchar_t dllPath[MAX_PATH] = { 0, };

	OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &tokenHandle);
	if (tokenHandle == NULL) {
		cerr << "tokenHandle" << endl;
		exit(1);
	};

	PRIVILEGE pv(tokenHandle);
	if (!pv.SetPrivilege(SE_DEBUG_NAME, TRUE)) {
		cerr << "SetPrivilege" << endl;
		exit(1);
	};

	cout << "DLL 경로 입력: ";
	//while (getchar() != '\n');
	_getws_s(dllPath);

	ij.SetDLLPath(dllPath);
	
	cout << "Process ID 입력 : ";
	cin >> pid;

	ij.SetPID(pid);
	ij.Injection(KERNEL);

	return 0;

};