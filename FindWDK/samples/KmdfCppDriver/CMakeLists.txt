cmake_minimum_required(VERSION 3.0)

list(APPEND CMAKE_MODULE_PATH "D:/Users/fayard/Desktop/driver_template-main/FindWDK/cmake")
find_package(WDK REQUIRED)

wdk_add_driver(KmdfCppDriver
    KMDF 1.15
    Main.cpp
    )
target_link_libraries(KmdfCppDriver KmdfCppLib)
 
 