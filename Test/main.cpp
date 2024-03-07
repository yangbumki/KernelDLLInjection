#include <Windows.h>
#include <iostream>

using namespace std;

BOOL SetForcePrivilege();
BOOL Injection(const DWORD pid, const wchar_t* dllPath);

int main() {
	DWORD pid = 0;

	auto result = SetForcePrivilege();
	if (!result) exit(1);

	std::cout << "PID : "; std::cin >> pid;
	Injection(pid, L"C:\\Users\\bgyang\\Desktop\\sourcecode\\KernelDLLInjection\\test.dll");

	return 0;
};

BOOL SetForcePrivilege() {
	HANDLE token = NULL;
	LUID luid = { 0, };
	TOKEN_PRIVILEGES tp = { 0, };

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token)) {
		cerr << "token" << endl;
		return FALSE;
	};

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
		cerr << "luid" << endl;
		return FALSE;
	};

	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid = luid;

	if (!AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		cerr << "tp" << endl;
		return FALSE;
	};

	return TRUE;
};

BOOL Injection(const DWORD pid, const wchar_t* dllPath) {
	HANDLE procHandle = NULL, remoteThreadHandle = NULL;
	HMODULE dll = NULL;
	void* procAddr = NULL, * injectionDLLPathAddr = NULL;

	procHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (procHandle == NULL) {
		cerr << "procHandle" << endl;
		return FALSE;
	};



	injectionDLLPathAddr = VirtualAllocEx(procHandle, NULL, MAX_PATH, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (injectionDLLPathAddr == NULL) {
		cerr << "injectionDLLPathAddr" << endl;
		return FALSE;
	}

	SIZE_T written = 0;

	if (!WriteProcessMemory(procHandle, injectionDLLPathAddr, dllPath, MAX_PATH, &written)) {
		cerr << "WriteProcessMemory" << endl;
		return FALSE;
	};

	dll = GetModuleHandle(L"kernel32.dll");
	if (dll == NULL) {
		cerr << "dll" << endl;
		return FALSE;
	};

	procAddr = GetProcAddress(dll, "LoadLibraryW");
	if (procAddr == NULL) {
		cerr << "procAddr" << endl;
		return FALSE;
	};

	remoteThreadHandle = CreateRemoteThread(procHandle, NULL, 0, (LPTHREAD_START_ROUTINE)procAddr, injectionDLLPathAddr, NULL, NULL);
	if (remoteThreadHandle == NULL) {
		cerr << "remoteThreadHandle" << endl;
		return FALSE;
	};

	WaitForSingleObject(remoteThreadHandle, INFINITY);
	
	CloseHandle(procHandle);
	
	return TRUE;
};