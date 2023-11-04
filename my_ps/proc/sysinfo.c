#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <locale.h>

#include <unistd.h>
#include <fcntl.h>

#ifndef HZ
#include <netinet/in.h>  /* htons */
#endif

long smp_num_cpus_;     /* number of CPUs */

#define BAD_OPEN_MESSAGE	"Error: /proc must be mounted\n"

#define STAT_FILE    "/proc/stat"
static int stat_fd = -1;
#define UPTIME_FILE  "/proc/uptime"
static int uptime_fd = -1;
#define BUFSIZE 2048
static char buf[BUFSIZE];

#define FILE_TO_BUF(filename, fd) do{				\
    static int local_n;						\
    if (fd == -1 && (fd = open(filename, O_RDONLY)) == -1) {	\
	fprintf(stderr, BAD_OPEN_MESSAGE);			\
	fflush(NULL);						\
	_exit(102);						\
    }								\
    lseek(fd, 0L, SEEK_SET);					\
    if ((local_n = read(fd, buf, sizeof buf - 1)) < 0) {	\
	perror(filename);					\
	fflush(NULL);						\
	_exit(103);						\
    }								\
    buf[local_n] = '\0';					\
}while(0)


/***********************************************************************/
int uptime() {
    double up=0, idle=0;
    char *savelocale;

    FILE_TO_BUF(UPTIME_FILE,uptime_fd);
    savelocale = setlocale(LC_NUMERIC, NULL);
    setlocale(LC_NUMERIC,"C");
    if (sscanf(buf, "%lf %lf", &up, &idle) < 2) {
        setlocale(LC_NUMERIC,savelocale);
	return 0;
    }
    setlocale(LC_NUMERIC,savelocale);
    return up;	/* assume never be zero seconds in practice */
}

unsigned long long Hertz_;

static void old_Hertz_hack(void){
  unsigned long long user_j, nice_j, sys_j, other_j;  /* jiffies (clock ticks) */
  double up_1, up_2, seconds;
  unsigned long long jiffies;
  unsigned h;
  char *savelocale;

  savelocale = setlocale(LC_NUMERIC, NULL);
  setlocale(LC_NUMERIC, "C");
  do{
    FILE_TO_BUF(UPTIME_FILE,uptime_fd);
    sscanf(buf, "%lf", &up_1);

    FILE_TO_BUF(STAT_FILE,stat_fd);
    sscanf(buf, "cpu %Lu %Lu %Lu %Lu", &user_j, &nice_j, &sys_j, &other_j);

    FILE_TO_BUF(UPTIME_FILE,uptime_fd);
    sscanf(buf, "%lf", &up_2);
  } while((long long)( (up_2-up_1)*1000.0/up_1 )); /* want under 0.1% error */
  setlocale(LC_NUMERIC, savelocale);
  jiffies = user_j + nice_j + sys_j + other_j;
  seconds = (up_1 + up_2) / 2;
  h = (unsigned)( (double)jiffies/seconds/smp_num_cpus_ );
  switch(h){
  case    9 ...   11 :  Hertz_ =   10; break; /* S/390 (sometimes) */
  case   18 ...   22 :  Hertz_ =   20; break; /* user-mode Linux */
  case   30 ...   34 :  Hertz_ =   32; break; /* ia64 emulator */
  case   48 ...   52 :  Hertz_ =   50; break;
  case   58 ...   61 :  Hertz_ =   60; break;
  case   62 ...   65 :  Hertz_ =   64; break; /* StrongARM /Shark */
  case   95 ...  105 :  Hertz_ =  100; break; /* normal Linux */
  case  124 ...  132 :  Hertz_ =  128; break; /* MIPS, ARM */
  case  195 ...  204 :  Hertz_ =  200; break; /* normal << 1 */
  case  253 ...  260 :  Hertz_ =  256; break;
  case  393 ...  408 :  Hertz_ =  400; break; /* normal << 2 */
  case  790 ...  808 :  Hertz_ =  800; break; /* normal << 3 */
  case  990 ... 1010 :  Hertz_ = 1000; break; /* ARM */
  case 1015 ... 1035 :  Hertz_ = 1024; break; /* Alpha, ia64 */
  case 1180 ... 1220 :  Hertz_ = 1200; break; /* Alpha */
  default:
#ifdef HZ
    Hertz_ = (unsigned long long)HZ;    /* <asm/param.h> */
#else
    /* If 32-bit or big-endian (not Alpha or ia64), assume HZ is 100. */
    Hertz_ = (sizeof(long)==sizeof(int) || htons(999)==999) ? 100UL : 1024UL;
#endif
    fprintf(stderr, "Unknown HZ value! (%d) Assume %Ld.\n", h, Hertz_);
  }
}

static void init_libproc(void) __attribute__((constructor));
static void init_libproc(void){
  smp_num_cpus_ = sysconf(_SC_NPROCESSORS_CONF); // or _SC_NPROCESSORS_ONLN
  if(smp_num_cpus_<1) smp_num_cpus_=1; /* SPARC glibc is buggy */

  old_Hertz_hack();
}
