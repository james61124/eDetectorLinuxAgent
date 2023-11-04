#ifndef NETSTAT_H
#define NETSTAT_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <netdb.h>
#include <pwd.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <unordered_set>
#include <string>

#include "../my_task/socket_send.h"

#include "lib/net-support.h"
#include "lib/pathnames.h"
#include "config.h"
#include "intl.h"
#include "lib/sysinfo.h"
#include "lib/util.h"
#include "lib/proc.h"
#define PROGNAME_WIDTH 100
#define PROGPID_WIDTH 20

#if !defined(s6_addr32) && defined(in6a_words)
#define s6_addr32 in6a_words	/* libinet6	*/
#endif

#define E_READ  -1
#define E_IOCTL -3




#define INFO_GUTS1(file,proc,prot)			\
  procinfo = proc_fopen((file));			\
  if (procinfo == NULL) {				\
    if (errno != ENOENT && errno != EACCES) {		\
      perror((file));					\
      return -1;					\
    }							\
    rc = 1;						\
  } else {						\
    do {						\
      if (fgets(buffer, sizeof(buffer), procinfo))	\
        (proc)(lnr++, buffer,prot);			\
    } while (!feof(procinfo));				\
    fclose(procinfo);					\
  }

/*#if HAVE_AFINET6
#define INFO_GUTS2(file,proc,prot)			\
  lnr = 0;						\
  procinfo = proc_fopen((file));		       	\
  if (procinfo != NULL) {				\
    do {						\
      if (fgets(buffer, sizeof(buffer), procinfo))	\
	(proc)(lnr++, buffer,prot);			\
    } while (!feof(procinfo));				\
    fclose(procinfo);					\
  }
#else
#define INFO_GUTS2(file,proc,prot)
#endif*/

#define INFO_GUTS3					\
 return rc;

#define INFO_GUTS6(file,file6,proc,prot4,prot6)	\
 char buffer[8192];					\
 int rc = 0;						\
 int lnr = 0;						\
 INFO_GUTS1(file,proc,prot4)				\
 /* INFO_GUTS2(file6,proc,prot6) */			\
 INFO_GUTS3

#define PROGNAME_WIDTHs PROGNAME_WIDTH1(PROGNAME_WIDTH)
#define PROGNAME_WIDTH1(s) PROGNAME_WIDTH2(s)
#define PROGNAME_WIDTH2(s) #s

#define PRG_HASH_SIZE 211



#define PRG_HASHIT(x) ((x) % PRG_HASH_SIZE)

#define PRG_LOCAL_ADDRESS	"local_address"
#define PRG_INODE		"inode"
#define PRG_SOCKET_PFX		"socket:["
#define PRG_SOCKET_PFXl		(strlen(PRG_SOCKET_PFX))
#define PRG_SOCKET_PFX2		"[0000]:"
#define PRG_SOCKET_PFX2l	(strlen(PRG_SOCKET_PFX2))


#ifndef LINE_MAX
#define LINE_MAX 4096
#endif

#define PATH_PROC	"/proc"
#define PATH_FD_SUFF	"fd"
#define PATH_FD_SUFFl	strlen(PATH_FD_SUFF)
#define PATH_PROC_X	PATH_PROC "/%s"
#define PATH_PROC_X_FD	PATH_PROC "/%s/" PATH_FD_SUFF
#define PATH_CMDLINE	"cmdline"
#define PATH_CMDLINEl	strlen(PATH_CMDLINE)

/* These enums are used by IPX too. :-( */
enum {
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING			/* now a valid state */
};



// void get_boot_time(void);
// int my_netstat();

class Netstat {
public:

    struct prg_node {
        struct prg_node *next;
        unsigned long inode;
        char name[PROGNAME_WIDTH];	// pid
        unsigned long socket_time;
        unsigned long prg_time;
    } *prg_hash[PRG_HASH_SIZE];
    
    Netstat(Info* infoInstance, SocketSend* socketSendInstance);
    Info* info;
    SocketSend* socketsend;

    FILE *procinfo;
    FILE * fp;
    std::unordered_set<std::string> netstat_info;
    unsigned long time_of_boot;


    void get_boot_time(void);
    int my_netstat();
    void stat2proc(const char *directory, unsigned long * prg_time);
    void prg_cache_add(unsigned long inode, char *name, unsigned long socket_time);
    void prg_cache_get(unsigned long inode, char *ret, int retSize, char *rem_addr);
    int extract_type_1_socket_inode(const char lname[], unsigned long * inode_p);
    int extract_type_2_socket_inode(const char lname[], unsigned long * inode_p);
    void prg_cache_load(void);
    void finish_this_one(char *rem_addr , unsigned long inode, char *local_port, int in_or_out_conn);
    const struct aftype *process_sctp_addr_str(const char *addr_str, struct sockaddr_storage *sas);
    void sctp_assoc_do_one(int lnr, char *line, const char *proto);
    int sctp_info_assocs(void);
    int sctp_info(void);
    void addr_do_one(char *buf, size_t buf_len, size_t short_len, const struct aftype *ap, const struct sockaddr_storage *addr, int port, const char *proto);
    void tcp_do_one(int lnr, const char *line, const char *prot);
    int tcp_info(void);
    void udp_do_one(int lnr, const char *line,const char *prot);
    int udp_info(void);
    int udplite_info(void);
    void raw_do_one(int lnr, const char *line,const char *prot);
    int raw_info(void);

private:
    int SendDataPacketToServer(const char* function, char* buff);




};

#endif // NETSTAT_H