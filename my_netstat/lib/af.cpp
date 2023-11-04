#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <unistd.h>
#include "../config.h"
#include "net-support.h"
#include "pathnames.h"
#include "../intl.h"
#include "util.h"

int flag_inet;
int flag_inet6;

extern struct aftype inet_aftype;
extern struct aftype inet6_aftype;

static short sVafinit = 0;

struct aftype * const aftypes[] =
{
#if HAVE_AFINET
    &inet_aftype,
#endif
#if HAVE_AFINET6
    &inet6_aftype,
#endif
    NULL
};

static void afinit(void)
{
#if HAVE_AFINET
    inet_aftype.title = _("DARPA Internet");
#endif
#if HAVE_AFINET6
    inet6_aftype.title = _("IPv6");
#endif
    sVafinit = 1;
}


/* Check our protocol family table for this family. */
const struct aftype *get_afntype(int af)
{
    struct aftype * const *afp;

    if (!sVafinit)
	afinit();

    afp = aftypes;
    while (*afp != NULL) {
	if ((*afp)->af == af)
	    return (*afp);
	afp++;
    }
    return (NULL);
}
