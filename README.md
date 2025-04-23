# hooklib64

A small Windows x86/x64, MSVC C++20 hook library based on [Detours](https://github.com/microsoft/detours) 4.0.1.

## Build System

The library is meant to be used as a third-party dependency in CMake via `FetchContent`.

Fetch directly from the Git repository:

```cmake
cmake_minimum_required(VERSION 3.20)
project(my_mod LANGUAGES CXX)
include(FetchContent)
FetchContent_Declare(hooklib
    GIT_REPOSITORY https://github.com/mos9527/hooklib64.git
    GIT_TAG HEAD # Or use a specific commit hash
)
FetchContent_MakeAvailable(hooklib)

# hooklib CMake targets and helper functions are now available.
add_library(my_mod SHARED mod.cpp)
target_link_libraries(my_mod PRIVATE hooklib::hooklib)
```

## Building 

Please use the Visual Studio generator with CMake 3.20 or later.

```powershell
# Build for x86
cmake -S . -B out/build/vs-x86 -G "Visual Studio 17 2022" -A Win32 -DHOOKLIB_BUILD_EXAMPLES=ON
cmake --build out/build/vs-x86 --config Release
# Build for x64
cmake -S . -B out/build/vs-x64 -G "Visual Studio 17 2022" -A x64 -DHOOKLIB_BUILD_EXAMPLES=ON
cmake --build out/build/vs-x64 --config Release
```

Similarly, Use `Visual Studio 18 2026` for VS2026. 

## Usage

See [Examples](./examples) for usage tutorials.

## DLL Proxies

`winhttp`, `d3d9`, `d3d10`, `d3d11`, `xinput1_3`, `winmm`, and `version` can be spoofed. Use the `hooklib_add_proxy` CMake helper function to add a proxy and have it built.

```cmake
add_library(my_mod SHARED mod.cpp)
# Builds `winhttp.dll` in the binary directory and links `hooklib::hooklib` to your target.
hooklib_add_proxy(my_mod winhttp)
```

Since `hooklib_add_proxy` also links `hooklib::hooklib`, meaning this should be all you need to introduce hooklib into your project!

## License

MIT. Detours' license is included in `detours/LICENSE`.
