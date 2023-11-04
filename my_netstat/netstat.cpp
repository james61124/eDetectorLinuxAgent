// #include <errno.h>
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <unistd.h>
// #include <ctype.h>
// #include <fcntl.h>
// #include <netdb.h>
// #include <pwd.h>
// #include <arpa/inet.h>
// #include <dirent.h>
// #include <time.h>
// #include <sys/types.h>
// #include <sys/stat.h>

// #include <unordered_set>
// #include <string>

// #include "lib/net-support.h"
// #include "lib/pathnames.h"
// #include "config.h"
// #include "intl.h"
// #include "lib/sysinfo.h"
// #include "lib/util.h"
// #include "lib/proc.h"
// #define PROGNAME_WIDTH 100
// #define PROGPID_WIDTH 20

// #if !defined(s6_addr32) && defined(in6a_words)
// #define s6_addr32 in6a_words	/* libinet6	*/
// #endif

// #define E_READ  -1
// #define E_IOCTL -3




// #define INFO_GUTS1(file,proc,prot)			\
//   procinfo = proc_fopen((file));			\
//   if (procinfo == NULL) {				\
//     if (errno != ENOENT && errno != EACCES) {		\
//       perror((file));					\
//       return -1;					\
//     }							\
//     rc = 1;						\
//   } else {						\
//     do {						\
//       if (fgets(buffer, sizeof(buffer), procinfo))	\
//         (proc)(lnr++, buffer,prot);			\
//     } while (!feof(procinfo));				\
//     fclose(procinfo);					\
//   }

// /*#if HAVE_AFINET6
// #define INFO_GUTS2(file,proc,prot)			\
//   lnr = 0;						\
//   procinfo = proc_fopen((file));		       	\
//   if (procinfo != NULL) {				\
//     do {						\
//       if (fgets(buffer, sizeof(buffer), procinfo))	\
// 	(proc)(lnr++, buffer,prot);			\
//     } while (!feof(procinfo));				\
//     fclose(procinfo);					\
//   }
// #else
// #define INFO_GUTS2(file,proc,prot)
// #endif*/

// #define INFO_GUTS3					\
//  return rc;

// #define INFO_GUTS6(file,file6,proc,prot4,prot6)	\
//  char buffer[8192];					\
//  int rc = 0;						\
//  int lnr = 0;						\
//  INFO_GUTS1(file,proc,prot4)				\
//  /* INFO_GUTS2(file6,proc,prot6) */			\
//  INFO_GUTS3

// #define PROGNAME_WIDTHs PROGNAME_WIDTH1(PROGNAME_WIDTH)
// #define PROGNAME_WIDTH1(s) PROGNAME_WIDTH2(s)
// #define PROGNAME_WIDTH2(s) #s

// #define PRG_HASH_SIZE 211



// #define PRG_HASHIT(x) ((x) % PRG_HASH_SIZE)

// #define PRG_LOCAL_ADDRESS	"local_address"
// #define PRG_INODE		"inode"
// #define PRG_SOCKET_PFX		"socket:["
// #define PRG_SOCKET_PFXl		(strlen(PRG_SOCKET_PFX))
// #define PRG_SOCKET_PFX2		"[0000]:"
// #define PRG_SOCKET_PFX2l	(strlen(PRG_SOCKET_PFX2))


// #ifndef LINE_MAX
// #define LINE_MAX 4096
// #endif

// #define PATH_PROC	"/proc"
// #define PATH_FD_SUFF	"fd"
// #define PATH_FD_SUFFl	strlen(PATH_FD_SUFF)
// #define PATH_PROC_X	PATH_PROC "/%s"
// #define PATH_PROC_X_FD	PATH_PROC "/%s/" PATH_FD_SUFF
// #define PATH_CMDLINE	"cmdline"
// #define PATH_CMDLINEl	strlen(PATH_CMDLINE)

// FILE *procinfo;
// FILE * fp;
// std::unordered_set<std::string> netstat_info;
// static unsigned long time_of_boot;

// static struct prg_node {
//     struct prg_node *next;
//     unsigned long inode;
//     char name[PROGNAME_WIDTH];	// pid
//     unsigned long socket_time;
//     unsigned long prg_time;
// } *prg_hash[PRG_HASH_SIZE];

#include "netstat.h"

Netstat::Netstat(Info* infoInstance, SocketSend* socketSendInstance) {
    info = infoInstance;
    socketsend = socketSendInstance;
}

void Netstat::stat2proc(const char *directory, unsigned long * prg_time) {
    static char filename[80], S[1024];
    int fd, num_read;
    time_t t;

    // read /proc/#/stat
    sprintf(filename, "%s/stat", directory);
    if ( (fd       = open(filename, O_RDONLY, 0)) == -1 ) return;
    if ( (num_read = read(fd, S, sizeof(S) - 1))      <= 0 ) num_read = -1;
    else S[num_read] = 0;
    close(fd);

    // parse stat data
    char* tmp = strrchr(S, ')');
    *tmp = '\0';

    char stat;
    int ppid, pgrp, session, tty, tpgid;
    long priority, nice, timeout, it_real_value;
    unsigned long flags, min_flt, cmin_flt, maj_flt, cmaj_flt;
    unsigned long long utime, stime, cutime, cstime, start_time;
    sscanf(tmp + 2,                     /* skip space after ')' too */
       "%c "
       "%d %d %d %d %d "
       "%lu %lu %lu %lu %lu "
       "%Lu %Lu %Lu %Lu "  /* utime stime cutime cstime */
       "%ld %ld %ld %ld "
       "%Lu ",  /* start_time */
       &stat,
       &ppid, &pgrp, &session, &tty, &tpgid,
       &flags, &min_flt, &cmin_flt, &maj_flt, &cmaj_flt,
       &utime, &stime, &cutime, &cstime,
       &priority, &nice, &timeout, &it_real_value,
       &start_time
    );

    t = time_of_boot + start_time / Hertz;
    *prg_time = t;
}

void Netstat::prg_cache_add(unsigned long inode, char *name, unsigned long socket_time)
{
    unsigned hi = PRG_HASHIT(inode);
    struct prg_node **pnp,*pn;
    char line[LINE_MAX];

    for (pnp = prg_hash + hi; (pn = *pnp); pnp = &pn->next) {
	if (pn->inode == inode)
	    return;
    }
    if (!(*pnp = static_cast<prg_node*>(malloc(sizeof(**pnp)))))
	return;

    char* tmp = strchr(name, ':');
    if (tmp != nullptr)
	*tmp = '\0';

    pn = *pnp;
    pn->next = NULL;
    pn->inode = inode;
    safe_strncpy(pn->name, name, sizeof(pn->name));
    pn->socket_time = socket_time;
    pn->prg_time = 0;

    snprintf(line, sizeof(line), PATH_PROC_X, name);
    stat2proc(line, &pn->prg_time);
}

void Netstat::prg_cache_get(unsigned long inode, char *ret, int retSize, char *rem_addr)
{
    unsigned hi = PRG_HASHIT(inode);
    struct prg_node *pn;

    snprintf(ret, retSize, "-|%s|0|0", rem_addr);
    for (pn = prg_hash[hi]; pn; pn = pn->next)
	if (pn->inode == inode)
	    snprintf(ret, retSize, "%s|%s|%lu|%lu", pn->name, rem_addr, pn->socket_time, pn->prg_time);
}

int Netstat::extract_type_1_socket_inode(const char lname[], unsigned long * inode_p) {

    /* If lname is of the form "socket:[12345]", extract the "12345"
       as *inode_p.  Otherwise, return -1 as *inode_p.
       */

    if (strlen(lname) < PRG_SOCKET_PFXl+3) return(-1);

    if (memcmp(lname, PRG_SOCKET_PFX, PRG_SOCKET_PFXl)) return(-1);
    if (lname[strlen(lname)-1] != ']') return(-1);

    {
        char inode_str[strlen(lname + 1)];  /* e.g. "12345" */
        const int inode_str_len = strlen(lname) - PRG_SOCKET_PFXl - 1;
        char *serr;

        strncpy(inode_str, lname+PRG_SOCKET_PFXl, inode_str_len);
        inode_str[inode_str_len] = '\0';
        *inode_p = strtoul(inode_str, &serr, 0);
        if (!serr || *serr || *inode_p == ~0)
            return(-1);
    }
    return(0);
}


int Netstat::extract_type_2_socket_inode(const char lname[], unsigned long * inode_p) {

    /* If lname is of the form "[0000]:12345", extract the "12345"
       as *inode_p.  Otherwise, return -1 as *inode_p.
       */

    if (strlen(lname) < PRG_SOCKET_PFX2l+1) return(-1);
    if (memcmp(lname, PRG_SOCKET_PFX2, PRG_SOCKET_PFX2l)) return(-1);

    {
        char *serr;

        *inode_p = strtoul(lname + PRG_SOCKET_PFX2l, &serr, 0);
        if (!serr || *serr || *inode_p == ~0)
            return(-1);
    }
    return(0);
}

void Netstat::prg_cache_load(void)
{
    char line[LINE_MAX], eacces=0;
    int procfdlen, /*fd, cmdllen, */lnamelen;
    char lname[30], cmdlbuf[512], finbuf[PROGNAME_WIDTH];
    unsigned long inode;
    const char *cs;//, *cmdlp;
    DIR *dirproc = NULL, *dirfd = NULL;
    struct dirent *direproc, *direfd;

    struct stat lst;
    unsigned long socket_time;

    cmdlbuf[sizeof(cmdlbuf) - 1] = '\0';
    if (!(dirproc=opendir(PATH_PROC))) return;
    while (errno = 0, direproc = readdir(dirproc)) {
	for (cs = direproc->d_name; *cs; cs++)
	    if (!isdigit(*cs))
		break;
	if (*cs)
	    continue;
	procfdlen = snprintf(line,sizeof(line),PATH_PROC_X_FD,direproc->d_name);
	if (procfdlen <= 0 || procfdlen >= sizeof(line) - 5)
	    continue;
	errno = 0;
	dirfd = opendir(line);
	if (! dirfd) {
	    if (errno == EACCES)
		eacces = 1;
	    continue;
	}
	line[procfdlen] = '/';
	//cmdlp = NULL;
	while ((direfd = readdir(dirfd))) {
            if (!isdigit(direfd->d_name[0]))
                continue;
	    if (procfdlen + 1 + strlen(direfd->d_name) + 1 > sizeof(line))
		continue;
	    memcpy(line + procfdlen - PATH_FD_SUFFl, PATH_FD_SUFF "/",
		PATH_FD_SUFFl + 1);
	    safe_strncpy(line + procfdlen + 1, direfd->d_name,
		sizeof(line) - procfdlen - 1);
	    lnamelen = readlink(line, lname, sizeof(lname) - 1);
	    if (lnamelen == -1)
		continue;
            lname[lnamelen] = '\0';  /*make it a null-terminated string*/

            if (extract_type_1_socket_inode(lname, &inode) < 0)
                if (extract_type_2_socket_inode(lname, &inode) < 0)
                    continue;

	    socket_time = 0;
            if (!lstat(line, &lst))
		socket_time = lst.st_atime;

	    /*if (!cmdlp) {
		if (procfdlen - PATH_FD_SUFFl + PATH_CMDLINEl >=
		    sizeof(line) - 5)
		    continue;
                safe_strncpy(line + procfdlen - PATH_FD_SUFFl, PATH_CMDLINE,
                    sizeof(line) - procfdlen + PATH_FD_SUFFl);
		fd = open(line, O_RDONLY);
		if (fd < 0)
		    continue;
		cmdllen = read(fd, cmdlbuf, sizeof(cmdlbuf) - 1);
		if (close(fd))
		    continue;
		if (cmdllen == -1)
		    continue;
		if (cmdllen < sizeof(cmdlbuf) - 1)
		    cmdlbuf[cmdllen]='\0';
		if (cmdlbuf[0] == '/' && (cmdlp = strrchr(cmdlbuf, '/')))
		    cmdlp++;
		else
		    cmdlp = cmdlbuf;
	    }*/

	    //snprintf(finbuf, sizeof(finbuf), "%s/%s", direproc->d_name, cmdlp);
	    snprintf(finbuf, sizeof(finbuf), "%s", direproc->d_name);
	    prg_cache_add(inode, finbuf, socket_time);
	}
	closedir(dirfd);
	dirfd = NULL;
    }
    if (dirproc)
	closedir(dirproc);
    if (dirfd)
	closedir(dirfd);
    if (!eacces)
	return;
}


// /* These enums are used by IPX too. :-( */
// enum {
//     TCP_ESTABLISHED = 1,
//     TCP_SYN_SENT,
//     TCP_SYN_RECV,
//     TCP_FIN_WAIT1,
//     TCP_FIN_WAIT2,
//     TCP_TIME_WAIT,
//     TCP_CLOSE,
//     TCP_CLOSE_WAIT,
//     TCP_LAST_ACK,
//     TCP_LISTEN,
//     TCP_CLOSING			/* now a valid state */
// };

#if HAVE_AFINET || HAVE_AFINET6

/*static const char *tcp_state[] =
{
    "",
    N_("ESTABLISHED"),
    N_("SYN_SENT"),
    N_("SYN_RECV"),
    N_("FIN_WAIT1"),
    N_("FIN_WAIT2"),
    N_("TIME_WAIT"),
    N_("CLOSE"),
    N_("CLOSE_WAIT"),
    N_("LAST_ACK"),
    N_("LISTEN"),
    N_("CLOSING")
};*/

//static void finish_this_one(int uid, unsigned long inode)
void Netstat::finish_this_one(char *rem_addr , unsigned long inode, char *local_port, int in_or_out_conn)
{
//  struct passwd *pw;
    char ret[100];

//  if ((pw = getpwuid(uid)) != NULL)
//	printf("|%s", pw->pw_name);
//  else
//	printf("|%d", uid);
//  prg_cache_get(inode, ret, sizeof ret);
    prg_cache_get(inode, ret, sizeof ret, rem_addr);
    if (*ret == '-')
	return;
    // printf("%s,,%d,,%s\n", ret, in_or_out_conn, local_port);
    fprintf(fp, "%s|%d|%s|%c", ret, in_or_out_conn, local_port, '\n');
    
    char* buffer = new char[DATASTRINGMESSAGELEN];
    sprintf(buffer, "%s|%d|%s", ret, in_or_out_conn, local_port);
    std::string target(buffer);

    if (netstat_info.find(target) == netstat_info.end()) {
        SendDataPacketToServer("GiveDetectNetwork", buffer);
        netstat_info.insert(target);
    }

    // netstat_info

    putchar('\n');
}

const struct aftype *Netstat::process_sctp_addr_str(const char *addr_str, struct sockaddr_storage *sas)
{
    if (strchr(addr_str,':')) {
#if HAVE_AFINET6
	extern struct aftype inet6_aftype;
	/* Demangle what the kernel gives us */
	struct in6_addr in6;
	char addr6_str[INET6_ADDRSTRLEN];
	unsigned u0, u1, u2, u3, u4, u5, u6, u7;
	sscanf(addr_str, "%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X",
	       &u0, &u1, &u2, &u3, &u4, &u5, &u6, &u7);
	in6.s6_addr16[0] = htons(u0);
	in6.s6_addr16[1] = htons(u1);
	in6.s6_addr16[2] = htons(u2);
	in6.s6_addr16[3] = htons(u3);
	in6.s6_addr16[4] = htons(u4);
	in6.s6_addr16[5] = htons(u5);
	in6.s6_addr16[6] = htons(u6);
	in6.s6_addr16[7] = htons(u7);

	inet_ntop(AF_INET6, &in6, addr6_str, sizeof(addr6_str));
	inet6_aftype.input(1, addr6_str, sas);
	sas->ss_family = AF_INET6;
#endif
    } else {
	struct sockaddr_in *sin = (struct sockaddr_in *)sas;
	sin->sin_addr.s_addr = inet_addr(addr_str);
	sas->ss_family = AF_INET;
    }
    return get_afntype(sas->ss_family);
}

void Netstat::sctp_assoc_do_one(int lnr, char *line, const char *proto)
{
    char buffer[1024];
    int state, lport, rport;
    unsigned long inode;

    const struct aftype *ap;
    struct sockaddr_storage localsas, remotesas;
    const char *sst_str;
    const char *txqueue_str;
    const char *rxqueue_str;
    const char *lport_str, *rport_str;
    const char *uid_str;
    const char *inode_str;
    char *laddrs_str;
    char *raddrs_str;

    if (lnr == 0) {
	/* ASSOC     SOCK   STY SST ST HBKT ASSOC-ID TX_QUEUE RX_QUEUE UID INODE LPORT RPORT LADDRS <-> RADDRS */
	return;
    }

    strtok(line, " \t\n");	/* skip assoc */
    strtok(0, " \t\n");		/* skip sock */
    strtok(0, " \t\n");		/* skip sty */
    sst_str = strtok(0, " \t\n");
    strtok(0, " \t\n");
    strtok(0, " \t\n");		/* skip hash bucket */
    strtok(0, " \t\n");		/* skip hash assoc-id */
    txqueue_str =  strtok(0, " \t\n");
    rxqueue_str =  strtok(0, " \t\n");
    uid_str = strtok(0, " \t\n");
    inode_str = strtok(0, " \t\n");
    lport_str = strtok(0, " \t\n");
    rport_str = strtok(0, " \t\n");
    laddrs_str = strtok(0, "<->\t\n");
    raddrs_str = strtok(0, "<->\t\n");

    if (!sst_str || !txqueue_str || !rxqueue_str || !uid_str ||
        !inode_str || !lport_str || !rport_str) {
	fprintf(stderr, _("warning, got bogus sctp assoc line.\n"));
	return;
    }

    state = atoi(sst_str);
    inode = strtoul(inode_str, 0, 0);
    lport = atoi(lport_str);
    rport = atoi(rport_str);

    if (htons(rport) == 0)
	return;

    /*print all addresses*/
    const char *this_local_addr;
    const char *this_remote_addr;
    char *ss1, *ss2;
    char local_port[16];
    char remote_port[16];

    snprintf(local_port, sizeof(local_port), "%s",
             get_sname(htons(lport), proto, FLAG_NUM_PORT));
    snprintf(remote_port, sizeof(remote_port), "%s",
             get_sname(htons(rport), proto, FLAG_NUM_PORT));

    this_local_addr = strtok_r(laddrs_str, " \t\n", &ss1);
    this_remote_addr = strtok_r(raddrs_str, " \t\n", &ss2);
    while (this_local_addr || this_remote_addr) {
	char local_addr[64];
	char remote_addr[64];

	if (this_local_addr) {
	    if (this_local_addr[0] == '*') {
		/* skip * */
		this_local_addr++;
	    }
	    ap = process_sctp_addr_str(this_local_addr, &localsas);
	    if (ap)
		safe_strncpy(local_addr,
		             ap->sprint(&localsas, FLAG_NUM_HOST|FLAG_NUM_PORT), sizeof(local_addr));
	    else
		sprintf(local_addr, _("unsupported address family %d"), localsas.ss_family);
	}
	if (this_remote_addr) {
	    if (this_remote_addr[0] == '*') {
		/* skip * */
		this_remote_addr++;
	    }
	    ap = process_sctp_addr_str(this_remote_addr, &remotesas);
	    if (ap)
		safe_strncpy(remote_addr,
		             ap->sprint(&remotesas, FLAG_NUM_HOST|FLAG_NUM_PORT), sizeof(remote_addr));
	    else
		sprintf(remote_addr, _("unsupported address family %d"), remotesas.ss_family);
	}

	if (this_remote_addr)
	    sprintf(buffer, "%s:%s", remote_addr, remote_port);

	//finish_this_one(uid, inode);
	finish_this_one(buffer, inode, local_port, state == 10 ? 1 : 0);

	this_local_addr = strtok_r(0, " \t\n", &ss1);
	this_remote_addr = strtok_r(0, " \t\n", &ss2);
    }
}

int Netstat::sctp_info_assocs(void)
{
    INFO_GUTS6(_PATH_PROCNET_SCTPASSOCS, _PATH_PROCNET_SCTP6ASSOCS,
               sctp_assoc_do_one, "sctp", "sctp6");
}

int Netstat::sctp_info(void)
{
    return sctp_info_assocs();
}

void Netstat::addr_do_one(char *buf, size_t buf_len, size_t short_len, const struct aftype *ap, const struct sockaddr_storage *addr, int port, const char *proto)
{
    const char *sport, *saddr;
    size_t port_len, addr_len;

    saddr = ap->sprint(addr, FLAG_NUM_HOST);
    sport = get_sname(htons(port), proto, FLAG_NUM_PORT);
    addr_len = strlen(saddr);
    port_len = strlen(sport);
    if (addr_len + port_len > short_len) {
	/* Assume port name is short */
	port_len = netmin(port_len, short_len - 4);
	addr_len = short_len - port_len;
	strncpy(buf, saddr, addr_len);
	buf[addr_len] = '\0';
	strcat(buf, ":");
	strncat(buf, sport, port_len);
    } 
    else
	snprintf(buf, buf_len, "%s:%s", saddr, sport);
}

void Netstat::tcp_do_one(int lnr, const char *line, const char *prot)
{
    unsigned long rxq, txq, time_len, retr, inode;
    int num, local_port, rem_port, d, state, uid, timer_run, timeout;
    char rem_addr[128], local_addr[128];
    const struct aftype *ap;
    struct sockaddr_storage localsas, remsas;
    struct sockaddr_in *localaddr = (struct sockaddr_in *)&localsas;
    struct sockaddr_in *remaddr = (struct sockaddr_in *)&remsas;
#if HAVE_AFINET6
    char addr6[INET6_ADDRSTRLEN];
    struct in6_addr in6;
    extern struct aftype inet6_aftype;
#endif

    if (lnr == 0)
	return;

    num = sscanf(line,
    "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu %*s\n",
		 &d, local_addr, &local_port, rem_addr, &rem_port, &state,
		 &txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode);

    if (num < 11) {
	fprintf(stderr, _("warning, got bogus tcp line.\n"));
	return;
    }

    if (htons(rem_port) == 0)
	return;

    if (strlen(local_addr) > 8) {
#if HAVE_AFINET6
	/* Demangle what the kernel gives us */
	sscanf(local_addr, "%08X%08X%08X%08X",
		&in6.s6_addr32[0], &in6.s6_addr32[1],
		&in6.s6_addr32[2], &in6.s6_addr32[3]);
	inet_ntop(AF_INET6, &in6, addr6, sizeof(addr6));
	inet6_aftype.input(1, addr6, &localsas);
	sscanf(rem_addr, "%08X%08X%08X%08X",
		&in6.s6_addr32[0], &in6.s6_addr32[1],
		&in6.s6_addr32[2], &in6.s6_addr32[3]);
	inet_ntop(AF_INET6, &in6, addr6, sizeof(addr6));
	inet6_aftype.input(1, addr6, &remsas);
	localsas.ss_family = AF_INET6;
	remsas.ss_family = AF_INET6;
#endif
    } else {
	sscanf(local_addr, "%X", &localaddr->sin_addr.s_addr);
	sscanf(rem_addr, "%X", &remaddr->sin_addr.s_addr);
	localsas.ss_family = AF_INET;
	remsas.ss_family = AF_INET;
    }

    if ((ap = get_afntype(localsas.ss_family)) == NULL) {
	fprintf(stderr, _("netstat: unsupported address family %d !\n"),
		localsas.ss_family);
	return;
    }

    addr_do_one(local_addr, sizeof(local_addr), 22, ap, &localsas, local_port, "tcp");
    addr_do_one(rem_addr, sizeof(rem_addr), 22, ap, &remsas, rem_port, "tcp");

    //printf("%-4s  %-*s %-*s %-11s", prot, (int)netmax(23,strlen(local_addr)), local_addr, (int)netmax(23,strlen(rem_addr)), rem_addr, _(tcp_state[state]));

    //finish_this_one(uid,inode);
    finish_this_one(rem_addr, inode, strrchr(local_addr, ':') + 1, state == 10 ? 1 : 0);
}

int Netstat::tcp_info(void)
{
    INFO_GUTS6(_PATH_PROCNET_TCP, _PATH_PROCNET_TCP6,
	       tcp_do_one, "tcp", "tcp6");
}


void Netstat::udp_do_one(int lnr, const char *line,const char *prot)
{
    char local_addr[128], rem_addr[128];
    //char *udp_state;
    int num, local_port, rem_port, d, state, timer_run, uid, timeout;
    struct sockaddr_storage localsas, remsas;
    struct sockaddr_in *localaddr = (struct sockaddr_in *)&localsas;
    struct sockaddr_in *remaddr = (struct sockaddr_in *)&remsas;
#if HAVE_AFINET6
    char addr6[INET6_ADDRSTRLEN];
    struct in6_addr in6;
    extern struct aftype inet6_aftype;
#endif
    const struct aftype *ap;
    unsigned long rxq, txq, time_len, retr, inode;

    if (lnr == 0)
	return;

    num = sscanf(line,
		 "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu %*s\n",
		 &d, local_addr, &local_port,
		 rem_addr, &rem_port, &state,
	  &txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode);

    if (num < 10) {
	fprintf(stderr, _("warning, got bogus udp line.\n"));
	return;
    }

    if (htons(rem_port) == 0)
	return;

    if (strlen(local_addr) > 8) {
#if HAVE_AFINET6
	sscanf(local_addr, "%08X%08X%08X%08X",
	       &in6.s6_addr32[0], &in6.s6_addr32[1],
	       &in6.s6_addr32[2], &in6.s6_addr32[3]);
	inet_ntop(AF_INET6, &in6, addr6, sizeof(addr6));
	inet6_aftype.input(1, addr6, &localsas);
	sscanf(rem_addr, "%08X%08X%08X%08X",
	       &in6.s6_addr32[0], &in6.s6_addr32[1],
	       &in6.s6_addr32[2], &in6.s6_addr32[3]);
	inet_ntop(AF_INET6, &in6, addr6, sizeof(addr6));
	inet6_aftype.input(1, addr6, &remsas);
	localsas.ss_family = AF_INET6;
	remsas.ss_family = AF_INET6;
#endif
    } else {
	sscanf(local_addr, "%X", &localaddr->sin_addr.s_addr);
	sscanf(rem_addr, "%X", &remaddr->sin_addr.s_addr);
	localsas.ss_family = AF_INET;
	remsas.ss_family = AF_INET;
    }

    //retr = 0L;

    if ((ap = get_afntype(localsas.ss_family)) == NULL) {
	printf( _("netstat: unsupported address family %d !\n"),
		localsas.ss_family);
	return;
    }
    /*switch (state) {
    case TCP_ESTABLISHED:
	udp_state = _("ESTABLISHED");
	break;

    case TCP_CLOSE:
	udp_state = "";
	break;

    default:
	udp_state = _("UNKNOWN");
	break;
    }*/

    addr_do_one(local_addr, sizeof(local_addr), 22, ap, &localsas, local_port, "udp");
    addr_do_one(rem_addr, sizeof(rem_addr), 22, ap, &remsas, rem_port, "udp");

    //printf("%-5s %-23s %-23s %-11s", prot, local_addr, rem_addr, udp_state);

    //finish_this_one(uid,inode);
    finish_this_one(rem_addr, inode, strrchr(local_addr, ':') + 1, state == 10 ? 1 : 0);
}

int Netstat::udp_info(void)
{
    INFO_GUTS6(_PATH_PROCNET_UDP, _PATH_PROCNET_UDP6,
	       udp_do_one, "udp", "udp6");
}

int Netstat::udplite_info(void)
{
    INFO_GUTS6(_PATH_PROCNET_UDPLITE, _PATH_PROCNET_UDPLITE6,
               udp_do_one, "udpl", "udpl6" );
}

void Netstat::raw_do_one(int lnr, const char *line,const char *prot)
{
    char local_addr[128], rem_addr[128];
    int num, local_port, rem_port, d, state, timer_run, uid, timeout;
    struct sockaddr_storage localsas, remsas;
    struct sockaddr_in *localaddr = (struct sockaddr_in *)&localsas;
    struct sockaddr_in *remaddr = (struct sockaddr_in *)&remsas;
#if HAVE_AFINET6
    char addr6[INET6_ADDRSTRLEN];
    struct in6_addr in6;
    extern struct aftype inet6_aftype;
#endif
    const struct aftype *ap;
    unsigned long rxq, txq, time_len, retr, inode;

    if (lnr == 0)
	return;

    num = sscanf(line,
		 "%d: %64[0-9A-Fa-f]:%X %64[0-9A-Fa-f]:%X %X %lX:%lX %X:%lX %lX %d %d %lu %*s\n",
		 &d, local_addr, &local_port, rem_addr, &rem_port, &state,
	  &txq, &rxq, &timer_run, &time_len, &retr, &uid, &timeout, &inode);

    if (num < 10) {
    	fprintf(stderr, _("warning, got bogus raw line.\n"));
	return;
    }

    if (htons(rem_port) == 0)
	return;

    if (strlen(local_addr) > 8) {
#if HAVE_AFINET6
    	sscanf(local_addr, "%08X%08X%08X%08X",
		&in6.s6_addr32[0], &in6.s6_addr32[1],
		&in6.s6_addr32[2], &in6.s6_addr32[3]);
	inet_ntop(AF_INET6, &in6, addr6, sizeof(addr6));
	inet6_aftype.input(1, addr6, &localsas);
	sscanf(rem_addr, "%08X%08X%08X%08X",
		&in6.s6_addr32[0], &in6.s6_addr32[1],
		&in6.s6_addr32[2], &in6.s6_addr32[3]);
	inet_ntop(AF_INET6, &in6, addr6, sizeof(addr6));
	inet6_aftype.input(1, addr6, &remsas);
	localsas.ss_family = AF_INET6;
	remsas.ss_family = AF_INET6;
#endif
    } else {
	sscanf(local_addr, "%X", &localaddr->sin_addr.s_addr);
	sscanf(rem_addr, "%X", &remaddr->sin_addr.s_addr);
	localsas.ss_family = AF_INET;
	remsas.ss_family = AF_INET;
    }

    if ((ap = get_afntype(localsas.ss_family)) == NULL) {
	fprintf(stderr, _("netstat: unsupported address family %d !\n"), localsas.ss_family);
	return;
    }

    addr_do_one(local_addr, sizeof(local_addr), 22, ap, &localsas, local_port, "raw");
    addr_do_one(rem_addr, sizeof(rem_addr), 22, ap, &remsas, rem_port, "raw");

    //printf("%-4s  %-23s %-23s %-11d",
    //       prot, local_addr, rem_addr, state);

    //finish_this_one(uid,inode);
    finish_this_one(rem_addr, inode, strrchr(local_addr, ':') + 1, state == 10 ? 1 : 0);
}

int Netstat::raw_info(void)
{
    INFO_GUTS6(_PATH_PROCNET_RAW, _PATH_PROCNET_RAW6,
	       raw_do_one, "raw", "raw6");
}

#endif

void Netstat::get_boot_time(void){
  unsigned long secs_since_boot	= uptime();
  unsigned long secs_since_1970	= time(NULL);
  time_of_boot = secs_since_1970 - secs_since_boot;
}


int Netstat::my_netstat() {
#if HAVE_AFINET
    fp = fopen("netstat.txt", "w+");
    while(true) {
        get_boot_time();
        prg_cache_load();
        tcp_info();
        sctp_info();
        udp_info();
        udplite_info();
        raw_info();
    }
#endif

    return 0;
}

int Netstat::SendDataPacketToServer(const char* function, char* buff) {
	char* functionName = new char[24];
	strcpy(functionName, function);
	return socketsend->SendDataToServer(functionName, buff);
}
