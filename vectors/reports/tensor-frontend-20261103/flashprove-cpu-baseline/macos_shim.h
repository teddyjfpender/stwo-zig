// macOS shim: blocks/coins/coins.h calls Linux getrandom(); provide it via getentropy (n <= 256).
#pragma once
#include <sys/types.h>
#include <sys/random.h>
#include <unistd.h>
inline ssize_t getrandom(void *p, size_t n, unsigned) { return getentropy(p, n) == 0 ? (ssize_t)n : -1; }
