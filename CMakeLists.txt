cmake_minimum_required(VERSION 3.30)
set(CMAKE_CXX_STANDARD 20)

project(hooklib)

include_directories(CMAKE_SOURCE_DIR .)
include_directories(${CMAKE_SOURCE_DIR}/detours/include)

add_library(dllmain SHARED dllmain.cpp)
target_link_libraries(dllmain PUBLIC ${CMAKE_SOURCE_DIR}/detours/lib/detours.lib)

function(copy_as name)
	# Copy dllmain.dll
	add_custom_command(TARGET dllmain POST_BUILD
		COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:dllmain> ${CMAKE_SOURCE_DIR}/artifacts/${name}
		COMMENT "Copying dllmain.dll to bin directory"
	)
endfunction()

copy_as(winhttp.dll)
copy_as(d3d9.dll)
copy_as(d3d10.dll)
copy_as(d3d11.dll)
copy_as(xinput1_3.dll)
copy_as(winhttp.dll)
copy_as(version.dll)