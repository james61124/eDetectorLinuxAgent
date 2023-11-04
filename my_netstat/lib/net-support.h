#ifndef NETSUPPORT_H
#define NETSUPPORT_H

/* This structure defines protocol families and their handlers. */
struct aftype {
    const char *name;
    const char *title;
    int af;
    int alen;
    const char *(*print) (const char *);
    const char *(*sprint) (const struct sockaddr_storage *, int numeric);
    int (*input) (int type, char *bufp, struct sockaddr_storage *);
    void (*herror) (const char *text);
    int (*rprint) (int options);
    int (*rinput) (int typ, int ext, char **argv);

    /* may modify src */
    int (*getmask) (char *src, struct sockaddr_storage *mask, char *name);

    int fd;
    const char *flag_file;
};

extern struct aftype * const aftypes[];

extern const struct aftype *get_afntype(int type);

#define FLAG_EXT       3		/* AND-Mask */
#define FLAG_NUM_HOST  4
#define FLAG_NUM_PORT  8
#define FLAG_NUM_USER 16
#define FLAG_NUM     (FLAG_NUM_HOST|FLAG_NUM_PORT|FLAG_NUM_USER)
#define FLAG_SYM      32
#define FLAG_CACHE    64
#define FLAG_FIB     128
#define FLAG_VERBOSE 256

extern const char *get_sname(int socknumber, const char *proto, int numeric);

extern int flag_inet;
extern int flag_inet6;

#define ESYSNOT(A,B)	fprintf(stderr, _("%s: no support for `%s' on this system.\n"),A,B)

#define E_NOTFOUND	8
#define E_SOCK		7
#define E_LOOKUP	6
#define E_VERSION	EXIT_SUCCESS
#define E_USAGE		EXIT_SUCCESS
#define E_OPTERR	3
#define E_INTERN	2
#define E_NOSUPP	1


/* End of lib/support.h */

#endif // NETSUPPORT_H

