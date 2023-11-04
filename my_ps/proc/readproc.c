#include "readproc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/dir.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <stdbool.h>

#define HASHSIZE        32                      /* power of 2 */
#define HASH(x)         ((x) & (HASHSIZE - 1))

#define NAMESIZE        20
#define NAMELENGTH      "19"

static struct pwbuf {
    struct pwbuf *next;
    uid_t uid;
    char name[NAMESIZE];
} *pwhash[HASHSIZE];

/**********************************************************************/

void *xcalloc(void *pointer, int size) {
    void * ret;
    if (pointer)
        free(pointer);
    if (!(ret = calloc(1, size))) {
        fprintf(stderr, "xcalloc: allocation error, size = %d\n", size);
        exit(1);
    }
    return ret;
}

void *xmalloc_s(unsigned int size, bool none) {
    void *p;

    if (size == 0)
        ++size;
    p = malloc(size);
    if (!p) {
        fprintf(stderr, "xmalloc: malloc(%d) failed", size);
        perror(NULL);
        exit(1);
    }
    return(p);
}

void *xrealloc(void *oldp, unsigned int size) {
    void *p;

    if (size == 0)
        ++size;
    p = realloc(oldp, size);
    if (!p) {
        fprintf(stderr, "xrealloc: realloc(%d) failed", size);
        perror(NULL);
        exit(1);
    }
    return(p);
}

/**********************************************************************/

char *user_from_uid(uid_t uid)
{
    struct pwbuf **p;
    struct passwd *pw;

    p = &pwhash[HASH(uid)];
    while (*p) {
        if ((*p)->uid == uid)
            return((*p)->name);
        p = &(*p)->next;
    }
    *p = (struct pwbuf *) xmalloc_s(sizeof(struct pwbuf), 0);
    (*p)->uid = uid;
    if ((pw = getpwuid(uid)) == NULL)
        sprintf((*p)->name, "#%d", uid);
    else
        sprintf((*p)->name, "%-." NAMELENGTH "s", pw->pw_name);
    (*p)->next = NULL;
    return((*p)->name);
}

static void status2proc (char* S, proc_t* P, int fill) {
    char* tmp;
    if (fill == 1) {
        memset(P->cmd, 0, sizeof P->cmd);
        sscanf (S, "Name:\t%15c", P->cmd);
        tmp = strchr(P->cmd,'\n');
        *tmp='\0';
        tmp = strstr (S,"State");
        sscanf (tmp, "State:\t%c", &P->state);
    }

    tmp = strstr (S,"Pid:");
    if(tmp) sscanf (tmp,
        "Pid:\t%d\n"
        "PPid:\t%d\n",
        &P->pid,
        &P->ppid
    );

    tmp = strstr (S,"Uid:");
    if(tmp) sscanf (tmp,
        "Uid:\t%d\t%d\t%d\t%d",
        &P->ruid, &P->euid, &P->suid, &P->fuid
    );
}


static void stat2proc(char* S, proc_t* P) {
    char* tmp = strrchr(S, ')');	/* split into "PID (cmd" and "<rest>" */
    *tmp = '\0';			/* replace trailing ')' with NUL */
    memset(P->cmd, 0, sizeof P->cmd);	/* clear even though *P xcalloc'd ?! */
    sscanf(S, "%d (%15c", &P->pid, P->cmd);   /* comm[16] in kernel */
    sscanf(tmp + 2,			/* skip space after ')' too */
       "%c "
       "%d %d %d %d %d "
       "%lu %lu %lu %lu %lu "
       "%Lu %Lu %Lu %Lu "  /* utime stime cutime cstime */
       "%ld %ld %ld %ld "
       "%Lu ",  /* start_time */
       &P->state,
       &P->ppid, &P->pgrp, &P->session, &P->tty, &P->tpgid,
       &P->flags, &P->min_flt, &P->cmin_flt, &P->maj_flt, &P->cmaj_flt,
       &P->utime, &P->stime, &P->cutime, &P->cstime,
       &P->priority, &P->nice, &P->timeout, &P->it_real_value,
       &P->start_time
    );
}

static int link2str(const char *dir, const char *what, char *ret, int cap) {
    static char filename[80];
    int num_read;

    sprintf(filename, "%s/%s", dir, what);
    if ( (num_read = readlink(filename, ret, cap - 1)) <= 0 ) num_read = -1;
    else {
	ret[num_read] = '\0';
	char* tmp = strrchr(ret, '(');
	if (tmp && *(tmp - 1) == ' ') {
	    *(tmp - 1) = '\0';
	    num_read = (int)(tmp - ret);
	}
    }

    return num_read;
}

static int file2str(const char *dir, const char *what, char *ret, int cap) {
    static char filename[80];
    int fd, num_read;

    sprintf(filename, "%s/%s", dir, what);
    if ( (fd       = open(filename, O_RDONLY, 0)) == -1 ) return -1;
    if ( (num_read = read(fd, ret, cap - 1))      <= 0 ) num_read = -1;
    else ret[num_read] = 0;
    close(fd);
    return num_read;
}

static char** file2strvec(const char* dir, const char* what) {
    char buf[2048];	/* read buf bytes at a time */
    char *p, *rbuf = 0, *endbuf, **q, **ret;
    int fd, tot = 0, n, c, end_of_file = 0;
    int align;

    sprintf(buf, "%s/%s", dir, what);
    if ( (fd = open(buf, O_RDONLY, 0) ) == -1 ) return NULL;

    /* read whole file into a memory buffer, allocating as we go */
    while ((n = read(fd, buf, sizeof buf - 1)) > 0) {
	if (n < (int)(sizeof buf - 1))
	    end_of_file = 1;
	if (n == 0 && rbuf == 0)
	    return NULL;	/* process died between our open and read */
	if (n < 0) {
	    if (rbuf)
		free(rbuf);
	    return NULL;	/* read error */
	}
	if (end_of_file && buf[n-1])		/* last read char not null */
	    buf[n++] = '\0';			/* so append null-terminator */
	rbuf = xrealloc(rbuf, tot + n);		/* allocate more memory */
	memcpy(rbuf + tot, buf, n);		/* copy buffer into it */
	tot += n;				/* increment total byte ctr */
	if (end_of_file)
	    break;
    }
    close(fd);
    if (n <= 0 && !end_of_file) {
	if (rbuf) free(rbuf);
	return NULL;		/* read error */
    }
    endbuf = rbuf + tot;			/* count space for pointers */
    align = (sizeof(char*)-1) - ((tot + sizeof(char*)-1) & (sizeof(char*)-1));
    for (c = 0, p = rbuf; p < endbuf; p++)
    	if (!*p)
	    c += sizeof(char*);
    c += sizeof(char*);				/* one extra for NULL term */

    rbuf = xrealloc(rbuf, tot + c + align);	/* make room for ptrs AT END */
    endbuf = rbuf + tot;			/* addr just past data buf */
    q = ret = (char**) (endbuf+align);		/* ==> free(*ret) to dealloc */
    *q++ = p = rbuf;				/* point ptrs to the strings */
    endbuf--;					/* do not traverse final NUL */
    while (++p < endbuf) 
    	if (!*p)				/* NUL char implies that */
	    *q++ = p+1;				/* next string -> next char */

    *q = 0;					/* null ptr list terminator */
    return ret;
}


proc_t* ps_readproc(PROCTAB* PT, proc_t* p) {
    static struct direct *ent;		/* dirent handle */
    static struct stat sb;		/* stat buffer */
    static char path[32], sbuf[1024];	/* bufs for stat,statm */

next_proc:				/* get next PID for consideration */

    while ((ent = readdir(PT->procfs)) &&
	(*ent->d_name < '0' || *ent->d_name > '9'));
    if (!ent || !ent->d_name)
	return NULL;
    sprintf(path, "/proc/%s", ent->d_name);

    if (stat(path, &sb) == -1)		/* no such dirent (anymore) */
	goto next_proc;

    if (!p)
	p = xcalloc(p, sizeof *p); 	/* passed buf or alloced mem */
    p->euid = sb.st_uid;		/* need a way to get real uid */

    if ((file2str(path, "stat", sbuf, sizeof sbuf)) == -1)
	goto next_proc;			/* error reading /proc/#/stat */
    stat2proc(sbuf, p);			/* parse /proc/#/stat */

    if ((file2str(path, "status", sbuf, sizeof sbuf)) != -1 )
        status2proc(sbuf, p, 0);

    strncpy(p->euser, user_from_uid(p->euid), sizeof p->euser);
    p->cmdline = file2strvec(path, "cmdline");
    p->environ = NULL;

    if ((link2str(path, "exe", sbuf, sizeof sbuf)) <= 0)
	strncpy(sbuf, "null", sizeof sbuf);
    strncpy(p->path, sbuf, sizeof p->path);
    
    return p;
}
