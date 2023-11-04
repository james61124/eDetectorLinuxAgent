#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

FILE *proc_fopen(const char *name)
{
    static char *buffer;
    static size_t pagesz;
    FILE *fd = fopen(name, "r");

    if (fd == NULL)
      return NULL;

    if (!buffer) {
      pagesz = getpagesize();
      buffer = static_cast<char*>(malloc(pagesz));
    }

    setvbuf(fd, buffer, _IOFBF, pagesz);
    return fd;
}
