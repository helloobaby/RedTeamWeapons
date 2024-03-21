Project(UserAdd)
add_library(UserAdd main.cxx samlib.h)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /ENTRY:DllMain")