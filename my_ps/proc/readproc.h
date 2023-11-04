typedef struct proc_t {
// 1st 16 bytes
    int
        pid,		/* process id */
    	ppid;		/* pid of parent process */
    unsigned
        pcpu;           /* %CPU usage (is not filled in by readproc!!!) */
    char
    	state;		/* single-char code for process state (S=sleeping) */
// 2nd 16 bytes
    unsigned long long
	utime,		/* user-mode CPU time accumulated by process */
	stime,		/* kernel-mode CPU time accumulated by process */
// and so on...
	cutime,		/* cumulative utime of process and reaped children */
	cstime,		/* cumulative stime of process and reaped children */
	start_time;	/* start time of process -- seconds since 1-1-70 */
    long
	priority,	/* kernel scheduling priority */
	timeout,	/* ? */
	nice,		/* standard unix nice level of process */
	it_real_value;	/* ? */
    unsigned long
	flags,		/* kernel flags for the process */
	min_flt,	/* number of minor page faults since process start */
	maj_flt,	/* number of major page faults since process start */
	cmin_flt,	/* cumulative min_flt of process and child processes */
	cmaj_flt;	/* cumulative maj_flt of process and child processes */
    char
	**environ,	/* environment string vector (/proc/#/environ) */
	**cmdline;	/* command line string vector (/proc/#/cmdline) */
    char
	/* Be compatible: Digital allows 16 and NT allows 14 ??? */
    	ruser[16],	/* real user name */
    	euser[16],	/* effective user name */
    	suser[16],	/* saved user name */
    	fuser[16],	/* filesystem user name */
    	cmd[16],	/* basename of executable file in call to exec(2) */
	path[1024];	/* exe real path (/proc/#/exe)  */
    int
        ruid,		/* real      */
        euid,		/* effective */
        suid,		/* saved     */
        fuid,		/* fs (used for file access only) */
	pgrp,		/* process group id */
	session,	/* session id */
	tty,		/* full device number of controlling terminal */
	tpgid;		/* terminal process group id */
} proc_t;

#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
typedef struct PROCTAB {
    DIR*	procfs;
} PROCTAB;

/* retrieve the next process matching the criteria set by the openproc()
 */
extern void *xrealloc(void *oldp, unsigned int size);
extern proc_t* ps_readproc(PROCTAB* PT, proc_t* return_buf);
