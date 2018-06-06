file(GLOB sources "*.c")
file(GLOB headers "*.h")
add_library(libjpeg ${sources} ${headers})
target_sources(libjpeg PRIVATE "unix/jmemname.c")
