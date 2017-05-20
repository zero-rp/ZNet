project(uv)
include_directories(./include ./src)
aux_source_directory(./src src)
add_library(uv STATIC ${src}
                    ./src/unix/async.c 
                   ./src/unix/atomic-ops.h 
                   ./src/unix/core.c 
                   ./src/unix/dl.c 
                   ./src/unix/fs.c 
                   ./src/unix/getaddrinfo.c 
                   ./src/unix/getnameinfo.c 
                   ./src/unix/internal.h 
                   ./src/unix/loop-watcher.c 
                   ./src/unix/loop.c 
                   ./src/unix/pipe.c 
                   ./src/unix/poll.c 
                   ./src/unix/process.c 
                   ./src/unix/signal.c 
                   ./src/unix/spinlock.h 
                   ./src/unix/stream.c 
                   ./src/unix/tcp.c 
                   ./src/unix/thread.c 
                   ./src/unix/timer.c 
                   ./src/unix/tty.c 
                   ./src/unix/udp.c
                   ./src/unix/linux-core.c
                   ./src/unix/linux-inotify.c
                   ./src/unix/linux-syscalls.c
                   ./src/unix/proctitle.c
)
set_target_properties(uv PROPERTIES output_name "uv")
