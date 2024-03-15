// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"
#include <iostream>

using namespace std;

//typedef BYTE	NTSTATUS;
//
//typedef struct _UNICODE_STRING
//{
//	USHORT Length;
//	USHORT MaximumLength;
//	_Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
//
//} UNICODE_STRING, * PUNICODE_STRING;
//
//typedef struct _OBJECT_ATTRIBUTES
//{
//	ULONG Length;
//	HANDLE RootDirectory;
//	PUNICODE_STRING ObjectName;
//	ULONG Attributes;
//	PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
//	PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
//} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
//
//typedef NTSTATUS(NTAPI* PUSER_THREAD_START_ROUTINE)(
//	_In_ PVOID ThreadParameter
//	);
//
//typedef struct _PS_ATTRIBUTE
//{
//	ULONG_PTR Attribute;
//	SIZE_T Size;
//	union
//	{
//		ULONG_PTR Value;
//		PVOID ValuePtr;
//	};
//	PSIZE_T ReturnLength;
//} PS_ATTRIBUTE, * PPS_ATTRIBUTE;
//
//typedef struct _PS_ATTRIBUTE_LIST
//{
//	SIZE_T TotalLength;
//	PS_ATTRIBUTE Attributes[1];
//} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;
//
//
//typedef NTSTATUS(*pNtCreateThreadEx)(
//	_Out_ PHANDLE ThreadHandle,
//	_In_ ACCESS_MASK DesiredAccess,
//	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
//	_In_ HANDLE ProcessHandle,
//	_In_ PUSER_THREAD_START_ROUTINE StartRoutine,
//	_In_opt_ PVOID Argument,
//	_In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
//	_In_ SIZE_T ZeroBits,
//	_In_ SIZE_T StackSize,
//	_In_ SIZE_T MaximumStackSize,
//	_In_opt_ PPS_ATTRIBUTE_LIST AttributeList
//	);

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "TEST", "TEST", NULL);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
};

//BOOL CallNtCreateRemoteThreadEx(HANDLE processHandle, LPTHREAD_START_ROUTINE remoteThreadFunc, LPVOID remoteBuf) {
//	HMODULE ntdll = NULL;
//	HANDLE threadHandle = NULL;
//	void* originFuncAddr = NULL;
//
//	ntdll = GetModuleHandle(L"ntdll.dll");
//	if (ntdll == NULL) {
//		cerr << "ntdll" << endl;
//		return FALSE;
//	};
//
//	originFuncAddr = GetProcAddress(ntdll, "NtCreateRemoteThreadEx");
//	if (originFuncAddr == NULL) {
//		cerr << "originFuncAddr" << endl;
//		return FALSE;
//	};
//
//	auto result = ((pNtCreateThreadEx)originFuncAddr)(&threadHandle, 0x1FFFFF, NULL, processHandle, (PUSER_THREAD_START_ROUTINE)remoteThreadFunc, remoteBuf, NULL, NULL, NULL, NULL, NULL);
//	if (result != 0) {
//		cerr << "NtCreateThrreadEx" << endl;
//		return FALSE;
//	};
//
//	return TRUE;
//};

