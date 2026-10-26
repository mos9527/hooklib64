cmake_minimum_required(VERSION 3.20)
project(hooklib VERSION 0.2.0 LANGUAGES CXX)

if(NOT WIN32 OR NOT MSVC)
	message(FATAL_ERROR "hooklib requires Windows and MSVC.")
endif()
if(CMAKE_CXX_COMPILER_ARCHITECTURE_ID MATCHES "ARM|IA64")
	message(FATAL_ERROR "hooklib supports only x86 and x64.")
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
	set(HOOKLIB_ARCH x64)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
	set(HOOKLIB_ARCH x86)
else()
	message(FATAL_ERROR "Unsupported pointer size.")
endif()

set(HOOKLIB_DETOURS_LIBRARY "" CACHE FILEPATH "Path to a Detours 4.0.1 library matching the target architecture")
set(_detours_library "${HOOKLIB_DETOURS_LIBRARY}")
if(NOT _detours_library)
	set(_detours_library "${CMAKE_CURRENT_SOURCE_DIR}/detours/lib/${HOOKLIB_ARCH}/detours.lib")
endif()
if(NOT EXISTS "${_detours_library}")
	message(FATAL_ERROR "Detours library for ${HOOKLIB_ARCH} not found: ${_detours_library}. Set HOOKLIB_DETOURS_LIBRARY to a matching library.")
endif()

add_library(hooklib_detours STATIC IMPORTED GLOBAL)
set_target_properties(hooklib_detours PROPERTIES
	IMPORTED_LOCATION "${_detours_library}"
	INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/detours/include"
)

add_library(hooklib INTERFACE)
add_library(hooklib::hooklib ALIAS hooklib)
target_compile_features(hooklib INTERFACE cxx_std_20)
target_include_directories(hooklib INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(hooklib INTERFACE hooklib_detours psapi)

function(hooklib_add_proxy target dll_name)
	if(NOT TARGET "${target}")
		message(FATAL_ERROR "hooklib_add_proxy requires an existing DLL target: ${target}")
	endif()
	get_target_property(_type "${target}" TYPE)
	if(NOT _type STREQUAL "SHARED_LIBRARY" AND NOT _type STREQUAL "MODULE_LIBRARY")
		message(FATAL_ERROR "hooklib_add_proxy requires a SHARED or MODULE library.")
	endif()
	get_target_property(_proxy "${target}" HOOKLIB_PROXY)
	if(_proxy)
		message(FATAL_ERROR "Target ${target} already has a hooklib proxy: ${_proxy}")
	endif()
	set(_supported winhttp d3d9 d3d10 d3d11 xinput1_3 winmm version)
	if(NOT dll_name IN_LIST _supported)
		message(FATAL_ERROR "Unsupported hooklib proxy: ${dll_name}. Expected one of: ${_supported}")
	endif()

	find_package(Python3 3.8 REQUIRED COMPONENTS Interpreter)
	set(_source_dir "${CMAKE_CURRENT_FUNCTION_LIST_DIR}")
	if(CMAKE_SIZEOF_VOID_P EQUAL 8)
		set(_arch x64)
	else()
		set(_arch x86)
	endif()
	set(_proxy_source "${CMAKE_CURRENT_BINARY_DIR}/hooklib-proxies/${target}/${dll_name}_exports.cpp")
	add_custom_command(OUTPUT "${_proxy_source}"
		COMMAND "${Python3_EXECUTABLE}" "${_source_dir}/tools/generate_proxy.py"
			--dll "${dll_name}" --arch "${_arch}" --format pragma --output "${_proxy_source}"
		DEPENDS "${_source_dir}/tools/generate_proxy.py"
		VERBATIM
		COMMENT "Generating ${_arch} ${dll_name}.dll linker pragmas from the build host"
	)
	add_custom_target("${target}_hooklib_proxy" DEPENDS "${_proxy_source}")
	add_dependencies("${target}" "${target}_hooklib_proxy")
	target_sources("${target}" PRIVATE "${_proxy_source}")
	set_source_files_properties("${_proxy_source}" PROPERTIES
		GENERATED TRUE
		SKIP_UNITY_BUILD_INCLUSION TRUE
		COMPILE_OPTIONS /utf-8
	)
	target_link_libraries("${target}" PRIVATE hooklib::hooklib)
	set_target_properties("${target}" PROPERTIES
		HOOKLIB_PROXY "${dll_name}"
		OUTPUT_NAME "${dll_name}"
		PREFIX ""
	)
endfunction()

option(HOOKLIB_BUILD_EXAMPLES "Build hooklib examples" OFF)
if(HOOKLIB_BUILD_EXAMPLES)
	add_executable(hooklib_runtime_example examples/01_runtime_function_loading.cpp)
	target_link_libraries(hooklib_runtime_example PRIVATE hooklib::hooklib)
	add_library(hooklib_example SHARED examples/02_win32_api_hooking.cpp)
	target_link_libraries(hooklib_example PRIVATE hooklib::hooklib shell32)
	if(HOOKLIB_ARCH STREQUAL "x64")
		add_library(hooklib_signature_example SHARED examples/03_signature_scan.cpp)
		target_link_libraries(hooklib_signature_example PRIVATE hooklib::hooklib)
	endif()
endif()
