#include <UWP/DumperIPC.hpp>

#include <iostream>
#include <array>
#include <atomic>
#include <thread>
#include <cstdarg>

/// API
namespace IPC
{
/// IPC Message Queue
MessageEntry::MessageEntry(const wchar_t* String)
{
	wcscpy_s(this->String, MessageEntry::StringSize, String);
}

template< typename QueueType, std::size_t PoolSize >
class AtomicQueue
{
public:
	using Type = QueueType;
	static constexpr std::size_t MaxSize = PoolSize;

	AtomicQueue()
		:
		Head(0),
		Tail(0)
	{ }

	~AtomicQueue()
	{ }

	void Enqueue(const Type& Entry)
	{
		while( Mutex.test_and_set(std::memory_order_acquire) )
		{
			std::this_thread::yield();
		}
		Entries[Tail] = Entry;
		Tail = (Tail + 1) % MaxSize;
		Mutex.clear(std::memory_order_release);
	}

	Type Dequeue()
	{
		while( Mutex.test_and_set(std::memory_order_acquire) )
		{
			std::this_thread::yield();
		}
		Type Temp = Entries[Head];
		Head = (Head + 1) % MaxSize;
		Mutex.clear(std::memory_order_release);
		return Temp;
	}

	std::size_t Size()
	{
		while( Mutex.test_and_set(std::memory_order_acquire) )
		{
			std::this_thread::yield();
		}
		Mutex.clear(std::memory_order_release);
		const std::size_t Result = Tail - Head;
		return Result;
	}

	bool Empty()
	{
		return Size() == 0;
	}

private:
	std::array<Type, MaxSize> Entries = {
		Type()
	};
	std::size_t Head = 0;
	std::size_t Tail = 0;
	std::atomic_flag Mutex = ATOMIC_FLAG_INIT;
};

////// Shared IPC Region //////////////////////////////////////////////////////
#pragma data_seg("SHARED")
AtomicQueue<MessageEntry, 1024> MessagePool = {};
std::atomic<std::size_t> CurMessageCount = 0;

// The process we are sending our data to
std::atomic<std::uint32_t> ClientProcess(0);

// The target UWP process we wish to dump
std::atomic<std::uint32_t> TargetProcess(0);

std::atomic<std::int32_t> TargetThread(InvalidThread);

#pragma data_seg()
#pragma comment(linker, "/section:SHARED,RWS")
///////////////////////////////////////////////////////////////////////////////

void SetClientProcess(std::uint32_t ProcessID)
{
	ClientProcess = ProcessID;
}

std::uint32_t GetClientProcess()
{
	return ClientProcess;
}

void SetTargetProcess(std::uint32_t ProcessID)
{
	TargetProcess = ProcessID;
}

std::uint32_t GetTargetProcess()
{
	return TargetProcess;
}

IPC_API void SetTargetThread(std::int32_t ThreadID)
{
	TargetThread = ThreadID;
}

IPC_API std::int32_t GetTargetThread()
{
	return TargetThread;
}

IPC_API void ClearTargetThread()
{
	TargetThread = InvalidThread;
}

// Message w/ status info
void PushMessage(ErrorStatus Error, float Progress, const wchar_t* Format, ...)
{
	std::va_list Args;
	MessageEntry Entry;

	va_start(Args, Format);
	vswprintf_s(
		Entry.String, Entry.StringSize,
		Format, Args
	);
	va_end(Args);

	Entry.Error = Error;
	Entry.Progress = Progress;

	MessagePool.Enqueue(Entry);
}

// Normal Message (default 'none' StatusError, 0% progress)
void PushMessage(const wchar_t* Format, ...)
{
	std::va_list Args;
	MessageEntry Entry;

	va_start(Args, Format);
	vswprintf_s(
		Entry.String, Entry.StringSize,
		Format, Args
	);
	va_end(Args);

	Entry.Error = ErrorStatus::none;
	Entry.Progress = 0.00;

	MessagePool.Enqueue(Entry);
}

bool PopMessage(std::wstring& Output, ErrorStatus &Error, float &Progress)
{
	if( MessageCount() )
	{
		const MessageEntry Entry = MessagePool.Dequeue();
		Output.assign(Entry.String, wcslen(Entry.String));
		Error = Entry.Error;
		Progress = Entry.Progress;

		return true;
	}
	return false;
}

std::size_t MessageCount()
{
	return MessagePool.Size();
}
}

