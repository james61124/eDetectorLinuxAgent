#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/dir.h>
#include <sys/types.h>

#include "proc/sysinfo.h"
#include "proc/readproc.h"

#define OUTBUF_SIZE 819200

typedef struct format_node {
  struct format_node *next;
  int (*pr)(void);                         /* print function */
} format_node;

typedef struct format_struct {
  const char *spec; /* format specifier */
  int (* const pr)(void); /* print function */
} format_struct;
