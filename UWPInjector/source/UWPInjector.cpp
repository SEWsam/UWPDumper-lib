#include <iostream>
#include <chrono>
#include <ctime>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>
#include <memory>
#include <chrono>
#include <filesystem>

#include <windows.h>
#include <psapi.h> //GetModuleFileNameEx
#include <TlHelp32.h>

#include <UWPInjector.hpp>

// Setting DLL access controls
#include <AccCtrl.h>
#include <Aclapi.h>
#include <Sddl.h>

// UWP
#include <atlbase.h>
#include <appmodel.h>

// IPC
#include <UWP/DumperIPC.hpp>

#define REPARSE_MOUNTPOINT_HEADER_SIZE   8

const wchar_t* DLLFile = L"UWPDumper.dll";

using ThreadCallback = bool(*)(
	std::uint32_t ThreadID,
	void* Data
	);

typedef struct {
	DWORD ReparseTag;
	DWORD ReparseDataLength;
	WORD Reserved;
	WORD ReparseTargetLength;
	WORD ReparseTargetMaximumLength;
	WORD Reserved1;
	WCHAR ReparseTarget[1];
} REPARSE_MOUNTPOINT_DATA_BUFFER, * PREPARSE_MOUNTPOINT_DATA_BUFFER;


static DWORD CreateJunction(LPCSTR szJunction, LPCSTR szPath)
{
	DWORD LastError = ERROR_SUCCESS;
	std::byte buf[sizeof(REPARSE_MOUNTPOINT_DATA_BUFFER) + MAX_PATH * sizeof(WCHAR)] = {};
	REPARSE_MOUNTPOINT_DATA_BUFFER& ReparseBuffer = (REPARSE_MOUNTPOINT_DATA_BUFFER&)buf;
	char szTarget[MAX_PATH] = "\\??\\";

	strcat_s(szTarget, szPath);
	// strcat_s(szTarget, "\\");

	if( !CreateDirectory(szJunction, nullptr) ) return GetLastError();

	// Obtain SE_RESTORE_NAME privilege (required for opening a directory)
	HANDLE hToken = nullptr;
	TOKEN_PRIVILEGES tp;
	try {
		if( !OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) throw GetLastError();
		if( !LookupPrivilegeValue(nullptr, SE_RESTORE_NAME, &tp.Privileges[0].Luid))  throw GetLastError();
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if( !AdjustTokenPrivileges(hToken, false, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr) )  throw GetLastError();
	}
	catch (DWORD LastError)
	{
		if( hToken ) CloseHandle(hToken);
		return LastError;
	}
	if( hToken ) CloseHandle(hToken);

	const HANDLE hDir = CreateFile(szJunction, GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
	if( hDir == INVALID_HANDLE_VALUE ) return GetLastError();

	ReparseBuffer.ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
	int32_t len = MultiByteToWideChar(CP_ACP, 0, szTarget, -1, ReparseBuffer.ReparseTarget, MAX_PATH);
	ReparseBuffer.ReparseTargetMaximumLength = static_cast<WORD>((len--) * sizeof(WCHAR));
	ReparseBuffer.ReparseTargetLength = static_cast<WORD>(len * sizeof(WCHAR));
	ReparseBuffer.ReparseDataLength = ReparseBuffer.ReparseTargetLength + 12;

	DWORD dwRet;
	if( !DeviceIoControl(hDir, FSCTL_SET_REPARSE_POINT, &ReparseBuffer, ReparseBuffer.ReparseDataLength + REPARSE_MOUNTPOINT_HEADER_SIZE, nullptr, 0, &dwRet, nullptr) )
	{
		LastError = GetLastError();
		CloseHandle(hDir);
		RemoveDirectory(szJunction);
		return LastError;
	}

	CloseHandle(hDir);
	return ERROR_SUCCESS;
}

void IterateThreads(ThreadCallback ThreadProc, std::uint32_t ProcessID, void* Data)
{
	void* hSnapShot = CreateToolhelp32Snapshot(
		TH32CS_SNAPTHREAD,
		ProcessID
	);

	if( hSnapShot == INVALID_HANDLE_VALUE )
	{
		return;
	}

	THREADENTRY32 ThreadEntry = { 0 };
	ThreadEntry.dwSize = sizeof(THREADENTRY32);
	Thread32First(hSnapShot, &ThreadEntry);
	do
	{
		if( ThreadEntry.th32OwnerProcessID == ProcessID )
		{
			const bool Continue = ThreadProc(
				ThreadEntry.th32ThreadID,
				Data
			);
			if( Continue == false )
			{
				break;
			}
		}
	}
	while( Thread32Next(hSnapShot, &ThreadEntry) );

	CloseHandle(hSnapShot);
}

void SetAccessControl(const std::wstring& ExecutableName, const wchar_t* AccessString)
{
	PSECURITY_DESCRIPTOR SecurityDescriptor = nullptr;
	EXPLICIT_ACCESSW ExplicitAccess = { 0 };

	ACL* AccessControlCurrent = nullptr;
	ACL* AccessControlNew = nullptr;

	SECURITY_INFORMATION SecurityInfo = DACL_SECURITY_INFORMATION;
	PSID SecurityIdentifier = nullptr;

	if(
		GetNamedSecurityInfoW(
			ExecutableName.c_str(),
			SE_FILE_OBJECT,
			DACL_SECURITY_INFORMATION,
			nullptr,
			nullptr,
			&AccessControlCurrent,
			nullptr,
			&SecurityDescriptor
		) == ERROR_SUCCESS
	)
	{
		ConvertStringSidToSidW(AccessString, &SecurityIdentifier);
		if( SecurityIdentifier != nullptr )
		{
			ExplicitAccess.grfAccessPermissions = GENERIC_READ | GENERIC_EXECUTE | GENERIC_WRITE;
			ExplicitAccess.grfAccessMode = SET_ACCESS;
			ExplicitAccess.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
			ExplicitAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
			ExplicitAccess.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
			ExplicitAccess.Trustee.ptstrName = reinterpret_cast<wchar_t*>(SecurityIdentifier);

			if(
				SetEntriesInAclW(
					1,
					&ExplicitAccess,
					AccessControlCurrent,
					&AccessControlNew
				) == ERROR_SUCCESS
			)
			{
				SetNamedSecurityInfoW(
					const_cast<wchar_t*>(ExecutableName.c_str()),
					SE_FILE_OBJECT,
					SecurityInfo,
					nullptr,
					nullptr,
					AccessControlNew,
					nullptr
				);
			}
		}
	}
	if( SecurityDescriptor )
	{
		LocalFree(reinterpret_cast<HLOCAL>(SecurityDescriptor));
	}
	if( AccessControlNew )
	{
		LocalFree(reinterpret_cast<HLOCAL>(AccessControlNew));
	}
}

bool DLLInjectRemote(uint32_t ProcessID, const std::wstring& DLLpath)
{
	const std::size_t DLLPathSize = ((DLLpath.size() + 1) * sizeof(wchar_t));
	std::uint32_t Result;
	if( !ProcessID )
	{
		std::wcout << "Invalid Process ID: " << ProcessID << std::endl;
		return false;
	}

	if( GetFileAttributesW(DLLpath.c_str()) == INVALID_FILE_ATTRIBUTES )
	{
		std::wcout << "DLL file: " << DLLpath << " does not exists" << std::endl;
		return false;
	}

	SetAccessControl(DLLpath, L"S-1-15-2-1");

	void* ProcLoadLibrary = reinterpret_cast<void*>(
		GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW")
	);

	if( !ProcLoadLibrary )
	{
		std::wcout << "Unable to find LoadLibraryW procedure" << std::endl;
		return false;
	}

	void* Process = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessID);
	if( Process == nullptr )
	{
		std::wcout << "Unable to open process ID" << ProcessID << " for writing" << std::endl;
		return false;
	}
	void* VirtualAlloc = reinterpret_cast<void*>(
		VirtualAllocEx(
			Process,
			nullptr,
			DLLPathSize,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_READWRITE
		)
	);

	if( VirtualAlloc == nullptr )
	{
		std::wcout << "Unable to remotely allocate memory" << std::endl;
		CloseHandle(Process);
		return false;
	}

	SIZE_T BytesWritten = 0;
	Result = WriteProcessMemory(
		Process,
		VirtualAlloc,
		DLLpath.data(),
		DLLPathSize,
		&BytesWritten
	);

	if( Result == 0 )
	{
		std::wcout << "Unable to write process memory" << std::endl;
		CloseHandle(Process);
		return false;
	}

	if( BytesWritten != DLLPathSize )
	{
		std::wcout << "Failed to write remote DLL path name" << std::endl;
		CloseHandle(Process);
		return false;
	}

	void* RemoteThread =
		CreateRemoteThread(
			Process,
			nullptr,
			0,
			reinterpret_cast<LPTHREAD_START_ROUTINE>(ProcLoadLibrary),
			VirtualAlloc,
			0,
			nullptr
		);

	// Wait for remote thread to finish
	if( RemoteThread )
	{
		// Explicitly wait for LoadLibraryW to complete before releasing memory
		// avoids causing a remote memory leak
		WaitForSingleObject(RemoteThread, INFINITE);
		CloseHandle(RemoteThread);
	}
	else
	{
		// Failed to create thread
		std::wcout << "Unable to create remote thread" << std::endl;
	}

	VirtualFreeEx(Process, VirtualAlloc, 0, MEM_RELEASE);
	CloseHandle(Process);
	return true;
}

std::wstring GetRunningDirectory()
{
	wchar_t RunPath[MAX_PATH];
	GetModuleFileNameW(GetModuleHandleW(nullptr), RunPath, MAX_PATH);
	PathRemoveFileSpecW(RunPath);
	return std::wstring(RunPath);
}


namespace UWPDumper
{

#pragma region class UWPInjector
	//private
	void UWPInjector::PackageQuery()
	{
		// Get package name
		if (
			HANDLE ProcessHandle = OpenProcess(
				PROCESS_ALL_ACCESS | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
				false, ProcessID
			); ProcessHandle
			)
		{
			std::uint32_t NameLength = 0;
			std::int32_t ProcessCode = GetPackageFamilyName(
				ProcessHandle, &NameLength, nullptr
			);
			if (NameLength)
			{
				std::unique_ptr<wchar_t[]> PackageName(new wchar_t[NameLength]());

				ProcessCode = GetPackageFamilyName(
					ProcessHandle, &NameLength, PackageName.get()
				);

				if (ProcessCode != ERROR_SUCCESS)
				{
					std::wcout << "GetPackageFamilyName Error: " << ProcessCode;
				}
				PackageFileName = PackageName.get();
			}
			CloseHandle(ProcessHandle);
		}
		else
		{
			std::cerr << "\033[91mFailed to query process info." << std::endl;

			int lasterror = GetLastError();
			if (lasterror == ERROR_ACCESS_DENIED)
			{
				std::cerr << "\033[91mYou are not running with full admin rights." << std::endl;
			}
			if (DebugSometimes)
			{
					std::cerr << "\033[33mDebug message: \033[91mError Code: " << lasterror << std::endl;
			}

			throw InjectorError::query;
		}
	}

	void UWPInjector::InitDumpFolder()
	{
		// Getting LocalAppData folder, creating junction

		char* LocalAppData;
		size_t len;
		errno_t err = _dupenv_s(&LocalAppData, &len, "LOCALAPPDATA");

		//get dump folder path
		std::filesystem::path DumpFolderPath(LocalAppData);
		DumpFolderPath.append("Packages");
		DumpFolderPath.append(PackageFileName);
		DumpFolderPath.append("TempState\\DUMP");
		//clear out dump folder
		std::filesystem::remove_all(DumpFolderPath);
		//create junction
		CreateJunction(DumpFolderPath.string().c_str(), TargetPath.string().c_str());
		//set acl for target directory
		SetAccessControl(TargetPath, L"S-1-15-2-1");
	}


	// public
	UWPInjector::UWPInjector(uint32_t pid, std::string path, bool verboseish) : ProcessID(pid), TargetPath(path), DebugSometimes(verboseish)
	{
		IPC::SetClientProcess(GetCurrentProcessId());

		UWPInjector::PackageQuery();
		UWPInjector::InitDumpFolder();

		SetAccessControl(GetRunningDirectory() + L'\\' + DLLFile, L"S-1-15-2-1");

		IPC::SetTargetProcess(ProcessID);

	}

	void UWPInjector::DumperInject()
	{
		std::cout << "\033[93mInjecting into remote process: ";
		if (!DLLInjectRemote(ProcessID, GetRunningDirectory() + L'\\' + DLLFile)) // this starts dump
		{
			std::cout << "\033[91mFailed" << std::endl;
			// system("pause");
			throw InjectorError::injection;
		}
		std::cout << "\033[92mSuccess!" << std::endl;

		std::cout << "\033[93mWaiting for remote thread IPC:" << std::endl;
		std::chrono::high_resolution_clock::time_point ThreadTimeout = std::chrono::high_resolution_clock::now() + std::chrono::seconds(5);
		while (IPC::GetTargetThread() == IPC::InvalidThread)
		{
			if (std::chrono::high_resolution_clock::now() >= ThreadTimeout)
			{
				std::cout << "\033[91mRemote thread wait timeout: Unable to find target thread" << std::endl;
				// system("pause");
				throw InjectorError::timeout;
			}
		}

		std::cout << "Remote Dumper thread found: 0x" << std::hex << IPC::GetTargetThread() << std::endl;
	}

	bool UWPInjector::PopMessage(std::wstring& Message, IPC::ErrorStatus& Error, float& Progress)
	{
		Message.reserve(IPC::MessageEntry::StringSize);

		if (IPC::PopMessage(Message, Error, Progress)) {
			return true;
		}

		return false;
	}

#pragma endregion
}