#pragma once
#include <iostream>
#include <UWP/DumperIPC.hpp>
#include <filesystem>

// Shortcut to avoid using IPC namespace outside library
namespace UWPDumper
{
	using DumperError = IPC::ErrorStatus;

	enum class InjectorError
	{
		query,
		injection,
		timeout

	};

	/// <summary>
	/// UWPInjector class for use in other projects
	/// </summary>
	/// <remarks> 
	/// Logging has been removed-- that can be implemented externally.
	/// </remarks>
	class UWPInjector
	{
	private:
		std::uint32_t ProcessID;
		std::filesystem::path TargetPath;

		std::wstring PackageFileName;

		void PackageQuery();
		void InitDumpFolder();

	public:
		UWPInjector(uint32_t pid, std::string path);

		inline bool ValidThread()
		{
			return (IPC::GetTargetThread() != IPC::InvalidThread);
		}

		void DumperInject();
		bool PopMessage(std::wstring& Message, IPC::ErrorStatus& Error, float& Progress);




	};
}