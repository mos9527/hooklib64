#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef HOOKLIB_MODULE_NAME
#define HOOKLIB_MODULE_NAME nullptr
#endif

#include <Windows.h>
#include <Psapi.h>
#include <detours.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>

namespace hooklib
{
namespace detail
{
template<typename Pointer, typename Address>
inline Pointer addressCast(Address address) noexcept
{
    static_assert(std::is_pointer_v<Pointer>);
    if constexpr (std::is_null_pointer_v<Address>)
        return nullptr;
    else
        return reinterpret_cast<Pointer>(address);
}

class ExclusiveLock
{
public:
    explicit ExclusiveLock(SRWLOCK& lock) noexcept : lock_(lock)
    {
        AcquireSRWLockExclusive(&lock_);
    }
    ~ExclusiveLock() { ReleaseSRWLockExclusive(&lock_); }
    ExclusiveLock(const ExclusiveLock&) = delete;
    ExclusiveLock& operator=(const ExclusiveLock&) = delete;

private:
    SRWLOCK& lock_;
};

inline SRWLOCK transactionLock = SRWLOCK_INIT;

inline bool readable(const MEMORY_BASIC_INFORMATION& region) noexcept
{
    if (region.State != MEM_COMMIT || (region.Protect & PAGE_GUARD))
        return false;
    switch (region.Protect & 0xff)
    {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

inline bool rangeEnd(std::uintptr_t begin, size_t size, std::uintptr_t& end) noexcept
{
    if (size > (std::numeric_limits<std::uintptr_t>::max)() - begin)
        return false;
    end = begin + size;
    return true;
}

inline void* scanSpan(const char* signature, const char* mask, size_t size,
    std::uintptr_t begin, size_t length) noexcept
{
    if (size > length)
        return nullptr;
    const auto* bytes = reinterpret_cast<const char*>(begin);
    for (size_t i = 0; i <= length - size; ++i)
    {
        size_t j = 0;
        while (j < size && (mask[j] == '?' || signature[j] == bytes[i + j]))
            ++j;
        if (j == size)
            return const_cast<char*>(bytes + i);
    }
    return nullptr;
}

inline LONG pinAddress(const void* address) noexcept
{
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
        reinterpret_cast<LPCWSTR>(address), &module))
        return static_cast<LONG>(GetLastError());
    return NO_ERROR;
}

inline LONG patchMemory(void* location, const void* data, size_t size, bool nop) noexcept
{
    std::uintptr_t end = 0;
    auto cursor = reinterpret_cast<std::uintptr_t>(location);
    if (!location || (!data && !nop) || size == 0 || !rangeEnd(cursor, size, end))
        return ERROR_INVALID_PARAMETER;

    const auto* source = static_cast<const unsigned char*>(data);
    while (cursor < end)
    {
        MEMORY_BASIC_INFORMATION region{};
        if (!VirtualQuery(reinterpret_cast<void*>(cursor), &region, sizeof(region)))
            return static_cast<LONG>(GetLastError());
        if (region.State != MEM_COMMIT || (region.Protect & PAGE_GUARD))
            return ERROR_INVALID_ADDRESS;
        std::uintptr_t regionEnd = 0;
        if (!rangeEnd(reinterpret_cast<std::uintptr_t>(region.BaseAddress), region.RegionSize, regionEnd)
            || regionEnd <= cursor)
            return ERROR_INVALID_ADDRESS;
        const size_t count = (regionEnd < end ? regionEnd : end) - cursor;
        auto* destination = reinterpret_cast<void*>(cursor);
        DWORD oldProtect = 0;
        if (!VirtualProtect(destination, count, PAGE_EXECUTE_READWRITE, &oldProtect))
            return static_cast<LONG>(GetLastError());
        if (nop)
            std::memset(destination, 0x90, count);
        else
            std::memcpy(destination, source, count);
        DWORD unused = 0;
        const LONG restoreError = VirtualProtect(destination, count, oldProtect, &unused)
            ? NO_ERROR : static_cast<LONG>(GetLastError());
        const LONG flushError = FlushInstructionCache(GetCurrentProcess(), destination, count)
            ? NO_ERROR : static_cast<LONG>(GetLastError());
        if (restoreError != NO_ERROR)
            return restoreError;
        if (flushError != NO_ERROR)
            return flushError;
        cursor += count;
        if (!nop)
            source += count;
    }
    return NO_ERROR;
}
}

inline bool getModuleInfo(const wchar_t* name, MODULEINFO& info) noexcept
{
    info = {};
    const HMODULE module = GetModuleHandleW(name);
    return module && GetModuleInformation(GetCurrentProcess(), module, &info, sizeof(info));
}

inline void* scan(const char* signature, const char* mask, size_t sigSize,
    void* memory, size_t memorySize) noexcept
{
    if (!signature || !mask || !memory)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return nullptr;
    }
    const size_t maskSize = std::strlen(mask);
    if (sigSize == 0)
        sigSize = maskSize;
    std::uintptr_t end = 0;
    auto cursor = reinterpret_cast<std::uintptr_t>(memory);
    if (sigSize == 0 || sigSize != maskSize || sigSize > memorySize
        || !detail::rangeEnd(cursor, memorySize, end))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return nullptr;
    }
    for (size_t i = 0; i < sigSize; ++i)
    {
        if (mask[i] != 'x' && mask[i] != '?')
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return nullptr;
        }
    }

    std::uintptr_t runBegin = cursor;
    bool inRun = false;
    while (cursor < end)
    {
        MEMORY_BASIC_INFORMATION region{};
        if (!VirtualQuery(reinterpret_cast<void*>(cursor), &region, sizeof(region)))
            return nullptr;
        std::uintptr_t regionEnd = 0;
        if (!detail::rangeEnd(reinterpret_cast<std::uintptr_t>(region.BaseAddress), region.RegionSize, regionEnd)
            || regionEnd <= cursor)
        {
            SetLastError(ERROR_INVALID_ADDRESS);
            return nullptr;
        }
        if (detail::readable(region))
        {
            if (!inRun)
                runBegin = cursor;
            inRun = true;
        }
        else if (inRun)
        {
            if (void* result = detail::scanSpan(signature, mask, sigSize, runBegin, cursor - runBegin))
            {
                SetLastError(ERROR_SUCCESS);
                return result;
            }
            inRun = false;
        }
        cursor = regionEnd < end ? regionEnd : end;
    }
    if (inRun)
    {
        if (void* result = detail::scanSpan(signature, mask, sigSize, runBegin, end - runBegin))
        {
            SetLastError(ERROR_SUCCESS);
            return result;
        }
    }
    SetLastError(ERROR_NOT_FOUND);
    return nullptr;
}

inline void* scanModule(const char* signature, const char* mask, std::uintptr_t hint = 0,
    const wchar_t* moduleName = nullptr) noexcept
{
    if (!signature || !mask)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return nullptr;
    }
    MODULEINFO info{};
    if (!getModuleInfo(moduleName, info))
        return nullptr;
    const size_t size = std::strlen(mask);
    const auto begin = reinterpret_cast<std::uintptr_t>(info.lpBaseOfDll);
    if (size != 0 && size <= info.SizeOfImage && hint >= begin
        && hint - begin <= info.SizeOfImage - size)
    {
        if (void* result = scan(signature, mask, size, reinterpret_cast<void*>(hint), size))
            return result;
    }
    return scan(signature, mask, size, info.lpBaseOfDll, info.SizeOfImage);
}

struct Pattern
{
    const char* bytes;
    const char* mask;
    size_t size;
};

template<size_t... Sizes>
constexpr auto makePatterns(const char (&...values)[Sizes]) noexcept
{
    constexpr size_t count = sizeof...(Sizes);
    static_assert(count > 0 && count % 2 == 0, "Expected signature/mask pairs.");
    constexpr std::array<size_t, count> sizes{ Sizes... };
    static_assert([sizes] {
        for (size_t i = 0; i < count; i += 2)
            if (sizes[i + 1] <= 1 || sizes[i] < sizes[i + 1])
                return false;
        return true;
    }(), "A signature must contain at least as many bytes as its nonempty mask.");
    const auto data = std::tuple{ std::string_view(values, Sizes - 1)... };
    return [&]<size_t... I>(std::index_sequence<I...>) {
        return std::array<Pattern, count / 2>{ Pattern{
            std::get<2 * I>(data).data(), std::get<2 * I + 1>(data).data(),
            std::get<2 * I + 1>(data).size() }... };
    }(std::make_index_sequence<count / 2>{});
}

template<size_t Count>
class Signature
{
public:
    constexpr Signature(std::array<Pattern, Count> patterns, std::uintptr_t hint = 0,
        const wchar_t* moduleName = nullptr) noexcept
        : patterns_(patterns), hint_(hint), moduleName_(moduleName) {}

    void* get() const noexcept
    {
        AcquireSRWLockShared(&lock_);
        void* result = address_;
        ReleaseSRWLockShared(&lock_);
        return result;
    }

    void* scan(bool force = false) noexcept
    {
        detail::ExclusiveLock guard(lock_);
        if (address_ && !force)
        {
            SetLastError(ERROR_SUCCESS);
            return address_;
        }
        address_ = nullptr;
        for (const Pattern& pattern : patterns_)
        {
            address_ = scanModule(pattern.bytes, pattern.mask, hint_, moduleName_);
            if (address_)
                break;
        }
        return address_;
    }

    Signature(const Signature&) = delete;
    Signature& operator=(const Signature&) = delete;

private:
    std::array<Pattern, Count> patterns_;
    std::uintptr_t hint_;
    const wchar_t* moduleName_;
    void* address_ = nullptr;
    mutable SRWLOCK lock_ = SRWLOCK_INIT;
};

template<typename Function>
class Hook
{
    static_assert(std::is_pointer_v<Function> && std::is_function_v<std::remove_pointer_t<Function>>);

public:
    using Resolver = Function (*)();

    constexpr Hook(Function& original, Function replacement, Resolver resolver = nullptr) noexcept
        : original_(original), replacement_(replacement), resolver_(resolver) {}

    LONG resolve(Function address) noexcept
    {
        detail::ExclusiveLock guard(lock_);
        if (installed_)
            return ERROR_ALREADY_EXISTS;
        if (!address)
            return ERROR_INVALID_ADDRESS;
        original_ = address;
        return NO_ERROR;
    }

    LONG install(std::initializer_list<HANDLE> threads = {}) noexcept
    {
        detail::ExclusiveLock guard(lock_);
        if (installed_)
            return NO_ERROR;
        if (!original_ && resolver_)
            original_ = resolver_();
        if (!original_ || !replacement_)
            return ERROR_INVALID_ADDRESS;

        detail::ExclusiveLock transactionGuard(detail::transactionLock);
        LONG error = detail::pinAddress(reinterpret_cast<const void*>(original_));
        if (error != NO_ERROR)
            return error;
        error = detail::pinAddress(reinterpret_cast<const void*>(replacement_));
        if (error != NO_ERROR)
            return error;
        error = detail::pinAddress(this);
        if (error != NO_ERROR)
            return error;
        error = detail::pinAddress(&original_);
        if (error != NO_ERROR)
            return error;
        error = DetourTransactionBegin();
        if (error != NO_ERROR)
            return error;
        error = DetourUpdateThread(GetCurrentThread());
        const DWORD currentThreadId = GetCurrentThreadId();
        for (HANDLE thread : threads)
        {
            if (error != NO_ERROR)
                break;
            if (!thread || thread == INVALID_HANDLE_VALUE)
            {
                error = ERROR_INVALID_HANDLE;
                continue;
            }
            const DWORD threadId = GetThreadId(thread);
            if (threadId == 0)
                error = static_cast<LONG>(GetLastError());
            else if (threadId != currentThreadId)
                error = DetourUpdateThread(thread);
        }
        if (error == NO_ERROR)
            error = DetourAttach(reinterpret_cast<PVOID*>(&original_), reinterpret_cast<PVOID>(replacement_));
        if (error != NO_ERROR)
        {
            const LONG abortError = DetourTransactionAbort();
            return abortError == NO_ERROR ? error : abortError;
        }
        error = DetourTransactionCommit();
        if (error == NO_ERROR)
            installed_ = true;
        return error;
    }

    Hook(const Hook&) = delete;
    Hook& operator=(const Hook&) = delete;

private:
    Function& original_;
    Function replacement_;
    Resolver resolver_;
    bool installed_ = false;
    SRWLOCK lock_ = SRWLOCK_INIT;
};

inline LONG writeMemory(void* location, const void* data, size_t size) noexcept
{
    return detail::patchMemory(location, data, size, false);
}

inline LONG writeNop(void* location, size_t count) noexcept
{
    return detail::patchMemory(location, nullptr, count, true);
}

inline FARPROC procAddress(const char* libraryName, const char* procName) noexcept
{
    if (!libraryName || !procName)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return nullptr;
    }
    HMODULE module = GetModuleHandleA(libraryName);
    if (!module)
        module = LoadLibraryA(libraryName);
    return module ? GetProcAddress(module, procName) : nullptr;
}

inline FARPROC procAddress(const wchar_t* libraryName, const char* procName) noexcept
{
    if (!libraryName || !procName)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return nullptr;
    }
    HMODULE module = GetModuleHandleW(libraryName);
    if (!module)
        module = LoadLibraryW(libraryName);
    return module ? GetProcAddress(module, procName) : nullptr;
}
}

inline const wchar_t* hooklibGetBaseName() noexcept
{
    thread_local wchar_t path[32768]{};
    const DWORD length = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
    if (length == 0)
        return nullptr;
    if (length >= std::size(path))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return nullptr;
    }
    const wchar_t* name = path;
    for (const wchar_t* cursor = path; *cursor; ++cursor)
        if (*cursor == L'\\' || *cursor == L'/')
            name = cursor + 1;
    return name;
}

inline bool hooklibIsProcess(const wchar_t* name) noexcept
{
    const wchar_t* current = hooklibGetBaseName();
    return name && current && lstrcmpiW(current, name) == 0;
}

inline const MODULEINFO* hooklibGetModuleInfo(const wchar_t* moduleName = nullptr) noexcept
{
    thread_local MODULEINFO info{};
    return hooklib::getModuleInfo(moduleName, info) ? &info : nullptr;
}

inline void* hooklibSigScan(const char* signature, const char* mask, size_t sigSize,
    void* memory, size_t memorySize) noexcept
{
    return hooklib::scan(signature, mask, sigSize, memory, memorySize);
}

inline void* hooklibSigScan(const char* signature, const char* mask, void* hint,
    const wchar_t* moduleName = nullptr) noexcept
{
    return hooklib::scanModule(signature, mask, reinterpret_cast<std::uintptr_t>(hint), moduleName);
}

#define HOOKLIB_IS_PROCESS(processName) hooklibIsProcess(processName)

#ifdef _DEBUG
#define HOOKLIB_LOG(fmt, ...) \
    do { \
        std::printf("[%s] ", __FILE__); \
        std::printf(fmt __VA_OPT__(,) __VA_ARGS__); \
        std::printf("\n"); \
    } while (false)
#else
#define HOOKLIB_LOG(fmt, ...) ((void)0)
#endif

namespace hooklib
{
namespace detail
{
template<auto Initialize>
inline DWORD WINAPI initializeThread(LPVOID)
{
    const LONG error = Initialize();
    HOOKLIB_LOG("hooklib initialization: %ld", error);
    return static_cast<DWORD>(error);
}
}

template<auto Initialize>
inline LONG initializeAsync() noexcept
{
    static_assert(std::is_invocable_r_v<LONG, decltype(Initialize)>,
        "Expected a no-argument initializer returning a LONG error code.");
    const HANDLE thread = CreateThread(nullptr, 0, detail::initializeThread<Initialize>, nullptr, 0, nullptr);
    if (!thread)
        return static_cast<LONG>(GetLastError());
    CloseHandle(thread);
    return NO_ERROR;
}
}

#define HOOKLIB_DLLMAIN() \
    extern "C" __declspec(dllexport) LONG WINAPI HooklibInitialize(); \
    extern "C" BOOL APIENTRY DllMain(HMODULE, DWORD reason, LPVOID) \
    { \
        return reason != DLL_PROCESS_ATTACH || hooklib::initializeAsync<HooklibInitialize>() == NO_ERROR; \
    } \
    extern "C" __declspec(dllexport) LONG WINAPI HooklibInitialize()

#define HOOKLIB_FUNCTION_PTR(returnType, callingConvention, function, location, ...) \
    returnType (callingConvention *function)(__VA_ARGS__) = \
        hooklib::detail::addressCast<returnType (callingConvention *)(__VA_ARGS__)>(location)

#define HOOKLIB_PROC_ADDRESS(libraryName, procName) hooklib::procAddress(libraryName, procName)

#define HOOKLIB_RUNTIME_FUNCTION(returnType, callingConvention, libraryName, procName, ...) \
    typedef returnType callingConvention _##procName(__VA_ARGS__); \
    _##procName* procName = reinterpret_cast<_##procName*>(HOOKLIB_PROC_ADDRESS(libraryName, #procName))

#define HOOKLIB_DECL_HOOK(returnType, callingConvention, functionName, ...) \
    typedef returnType callingConvention _##functionName(__VA_ARGS__); \
    inline constinit _##functionName* original##functionName = nullptr; \
    returnType callingConvention implOf##functionName(__VA_ARGS__); \
    inline constinit hooklib::Hook<_##functionName*> hook##functionName{ original##functionName, implOf##functionName }

#define HOOKLIB_HOOK(returnType, callingConvention, functionName, location, ...) \
    typedef returnType callingConvention _##functionName(__VA_ARGS__); \
    inline constinit _##functionName* original##functionName = nullptr; \
    returnType callingConvention implOf##functionName(__VA_ARGS__); \
    inline constinit hooklib::Hook<_##functionName*> hook##functionName{ original##functionName, implOf##functionName, \
        +[]() -> _##functionName* { return hooklib::detail::addressCast<_##functionName*>(location); } }; \
    returnType callingConvention implOf##functionName(__VA_ARGS__)

#define HOOKLIB_RESOLVE_HOOK(functionName, location) \
    hook##functionName.resolve(hooklib::detail::addressCast<_##functionName*>(location))

#define HOOKLIB_INSTALL_HOOK(functionName, ...) hook##functionName.install({ __VA_ARGS__ })

#define HOOKLIB_WRITE_MEMORY(location, type, ...) \
    ([&]() -> LONG { \
        const type data[] = { __VA_ARGS__ }; \
        return hooklib::writeMemory(hooklib::detail::addressCast<void*>(location), data, sizeof(data)); \
    }())

#define HOOKLIB_WRITE_NOP(location, count) \
    hooklib::writeNop(hooklib::detail::addressCast<void*>(location), static_cast<size_t>(count))

#define HOOKLIB_SIG_DECL_MODULE(name, moduleName, hint, ...) \
    inline constinit hooklib::Signature name##Signature{ hooklib::makePatterns(__VA_ARGS__), \
        static_cast<std::uintptr_t>(hint), moduleName }; \
    inline void* name() noexcept { return name##Signature.get(); }

#define HOOKLIB_SIG_DECL(name, hint, ...) \
    HOOKLIB_SIG_DECL_MODULE(name, HOOKLIB_MODULE_NAME, hint, __VA_ARGS__)

#define HOOKLIB_SIG_SCAN(name) name##Signature.scan()
#define HOOKLIB_SIG_RETRY(name) name##Signature.scan(true)
