cmake_minimum_required(VERSION 3.15)
 
 
add_compile_options(/GS-)
project(CopeDriver LANGUAGES CXX ASM_MASM  )

 
#add_subdirectory(Usermode) 

ADD_DEFINITIONS(-DUNICODE)
ADD_DEFINITIONS(-D_UNICODE)


SET(CMAKE_COLOR_MAKEFILE ON)
# And optionally
SET(CMAKE_VERBOSE_MAKEFILE ON)
set(NTDDI_VERSION NTDDI_WIN2K)

# Include FindWDK
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/FindWDK/cmake")
find_package(WDK REQUIRED)
 
# Treat warnings as errors
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4 /WX /GS- /wd4100 /wd4101")

file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS src/*)
file(GLOB_RECURSE INCLUDES CONFIGURE_DEPENDS include/*)

set(NTD_win10 0x0A000008 )
set(WINNIT 0x0A00 )


add_compile_options(-Wno-unused-parameter)
# Create driver
 


wdk_add_driver(CopeDriver 
	${SOURCES}
	${INCLUDES}
	NTDDI_VERSION ${NTD_win10}
	
)
target_link_options(CopeDriver PRIVATE "/SAFESEH:NO" "/NXCOMPAT:NO" "/INCREMENTAL:NO" "/INTEGRITYCHECK:NO" )

file( GLOB deathCorp "src/DeadCorp/*.cpp")  
source_group(TREE ${PROJECT_SOURCE_DIR} FILES ${SOURCES} ${INCLUDES}  deathCorp )
 
set_target_properties(CopeDriver PROPERTIES LINK_FLAGS "/ENTRY:CopeDriver")
# Enable std20
target_compile_features(CopeDriver PRIVATE
	cxx_std_20
)
target_precompile_headers(CopeDriver PUBLIC src/DeadCorp/defines.h src/DeadCorp/arch.h)
target_link_libraries(CopeDriver  WDK::NTOSKRNL  )
target_include_directories(CopeDriver PRIVATE
	include
)

 

# link against for CopeLibrary  
#Ws2_32.Lib Wldap32.Lib Crypt32.Lib 
 
 

# TERMINAL GUIDE AND PASTES  .........................................

# libmerging :  lib.exe /out:MERGED.lib  first.lib second.lib
# 
# libmerging :  lib.exe /out:DEBUG_DEP2.lib  DEBUG_DEP.lib zip.lib bz2.lib
# libmerging :  lib.exe /out:RELEASE_DEP2.lib  RELEASE_DEP.lib zip.lib bz2.lib
#
#

# END 

# CMAKE GUIDE AND PASTES  ............................................

#set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

# include(linkcommon.cmake)
# set(CMAKE_VERBOSE_MAKEFILE ON) 
# set(CMAKE_CXX_STANDARD 17)
# ADD_DEFINITIONS(-DUNICODE) ADD_DEFINITIONS(-D_UNICODE)
#
# set(CMAKE_GENERATE_PDB_FILE ON)
# set(CMAKE_PDB_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/build")
# set(CMAKE_RUNTIME_OUTPUT_DIRECTORY)
#    file( GLOB cs "Parasite5/copeshot/*.cpp")  
#include_directories(
 # "${CMAKE_CURRENT_SOURCE_DIR}/folder..."
#)    

# END