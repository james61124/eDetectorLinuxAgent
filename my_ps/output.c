#include "common.h"
#include "output.h"

#define PROC_HASH_SIZE 256
#define PROC_HASHIT(x) ((x) % PROC_HASH_SIZE)

static struct proc_node {
    struct proc_node *next;
    int pid;
    char name[32];
    unsigned long time;
    char path[512];
} *proc_hash[PROC_HASH_SIZE];

static struct proc_pr_later {
    struct proc_pr_later *next;
    proc_t *p;
} *proc_later_list;

static proc_t *pp;     /* the process being printed */

static unsigned long seconds_since_boot = -1;
static unsigned long seconds_since_1970;
static unsigned long time_of_boot;
static int need_record = 0;

static format_node    *format_list = (format_node *)0xdeadbeef;

/***************************************************************************/

FILE * fp_out;

int simple_escape_str(char *dst, const char *src, size_t n){
  unsigned char c;
  size_t i;
  const char *codes =
  "Z-------------------------------"
  "********************************"
  "********************************"
  "*******************************-"
  "--------------------------------"
  "********************************"
  "********************************"
  "********************************";
  for(i=0; i<n;){
    c = (unsigned char) *(src++);
    switch(codes[c]){
    case 'Z':
      goto leave;
    case '*':
      i++;
      *(dst++) = c;
      break;
    case '-':
      i++;
      *(dst++) = '?';
      break;
    }
  }
leave:
  *(dst++) = '\0';
  return i;
}

static char** strvec_cpy(char** cmdline) {
  char *p, *rbuf = 0, *endbuf, **q, **ret = NULL;
  int tot = 0, n, c, align;
  const char **lc = (const char**)cmdline;
  if(lc && *lc) {
    while(*lc){
      n = strlen(*lc);
      rbuf = xrealloc(rbuf, tot + n + 1);
      memcpy(rbuf + tot, *lc, n);
      tot += n;
      rbuf[tot++] = '\0';
      lc++;
    }
    endbuf = rbuf + tot;
    align = (sizeof(char*)-1) - ((tot + sizeof(char*)-1) & (sizeof(char*)-1));
    for (c = 0, p = rbuf; p < endbuf; p++)
        if (!*p)
            c += sizeof(char*);
    c += sizeof(char*);

    rbuf = xrealloc(rbuf, tot + c + align);
    endbuf = rbuf + tot;
    q = ret = (char**) (endbuf+align);
    *q++ = p = rbuf;
    endbuf--;
    while (++p < endbuf)
        if (!*p)
            *q++ = p+1;

    *q = 0;
  }
  return ret;
}

/***************************************************************************/

static void proc_cache_add(int pid, char *name, unsigned long long time, char *path) {
    unsigned hi = PROC_HASHIT(pid);
    struct proc_node **pnp, *pn;

    for (pnp = proc_hash + hi; (pn = *pnp); pnp = &pn->next) {
        if (pn->pid == pid)
            return;
    }
    if (!(*pnp = malloc(sizeof(**pnp))))
        return;

    time_t t = time_of_boot + time / Hertz_;
    char* tmp = strchr(name, ':');
    if (tmp > 0) 
        *tmp = '\0';

    pn = *pnp;
    pn->next = NULL;
    pn->pid = pid;
    snprintf(pn->name, sizeof(pn->name), "%s", name);
    pn->time = t;
    snprintf(pn->path, sizeof(pn->path), "%s", path);
}

static void proc_cache_get(int pid, char *ret, int retSize)
{
    unsigned hi = PROC_HASHIT(pid);
    struct proc_node *pn;

    snprintf(ret, retSize, "null|0");
    for (pn = proc_hash[hi]; pn; pn = pn->next)
        if (pn->pid == pid)
            snprintf(ret, retSize, "%s|%s", pn->name, pn->path);
}

/***************************************************************************/

static int pr_args(void){
  const char **lc = (const char**)pp->cmdline; /* long version */
  if(lc && *lc) {
    char tmp[OUTBUF_SIZE];
    size_t i = 0;
    while(*lc){
      i += simple_escape_str(tmp+i, *lc, OUTBUF_SIZE-i);
      if((OUTBUF_SIZE-i > 1) && (*(lc+1))) tmp[i++] = ' ';
      lc++;
    }
    fprintf(fp_out, "%s", tmp);
  } else {
    fprintf(fp_out, "[%s]", pp->cmd);
  }
  return 0;
}

static int pr_etime(void){
  unsigned long t;
  unsigned dd,hh,mm,ss;
  t = seconds_since_boot - (unsigned long)(pp->start_time / Hertz_);
  ss = t%60;
  t /= 60;
  mm = t%60;
  t /= 60;
  hh = t%24;
  t /= 24;
  dd = t;
  fprintf(fp_out, "%u-%02u:%02u:%02u", dd, hh, mm, ss);
  return 0;
}

static int pr_c(void){
  unsigned long long total_time;   /* jiffies used by this process */
  unsigned pcpu = 0;               /* scaled %cpu, 99 means 99% */
  unsigned long long seconds;      /* seconds of process life */
  total_time = pp->utime + pp->stime;
  total_time += (pp->cutime + pp->cstime);
  seconds = seconds_since_boot - pp->start_time / Hertz_;
  if(seconds) pcpu = (total_time * 100ULL / Hertz_) / seconds;
  if (pcpu > 99U) pcpu = 99U;
  fprintf(fp_out, "%u", pcpu);
  return 0;
}

static int pr_pid(void){
  fprintf(fp_out, "%u", pp->pid);
  return 0;
}

static int pr_ppid(void){
  fprintf(fp_out, "%u", pp->ppid);
  return 0;
}

static int pr_time(void){
  unsigned long t;
  unsigned dd,hh,mm,ss;
  int c = 0;
  t = (pp->utime + pp->stime) / Hertz_;
  t += (pp->cutime + pp->cstime);
  ss = t%60;
  t /= 60;
  mm = t%60;
  t /= 60;
  hh = t%24;
  t /= 24;
  dd = t;
  fprintf(fp_out, "%u-%02u:%02u:%02u", dd, hh, mm, ss);
  return c;
}

static int pr_euser(void){
    fprintf(fp_out, "%s", pp->euser);
    return 0;
}

static int pr_stat(void){
    fprintf(fp_out, "%c", pp->state);
    return 0;
}

static int old_time_helper(unsigned long long t, unsigned long long rel) {
  if(!t)            return fprintf(fp_out, "NULL");
  if(t == ~0ULL)    return fprintf(fp_out, "xx");
  if((long long)(t-=rel) < 0)  t=0ULL;
  if(t>9999ULL)     return fprintf(fp_out, "%5Lu", t/100ULL);
  else              return fprintf(fp_out, "%2u.%02u", (unsigned)t/100U, (unsigned)t%100U);
}

static int pr_timeout(void){
    return old_time_helper(pp->timeout, seconds_since_boot*Hertz_);
}

static int pr_lstart(void){
  time_t t;
  t = time_of_boot + pp->start_time / Hertz_;
  //printf("%24.24s", ctime(&t));
  fprintf(fp_out, "%lu", t);
  return 0;
}

static int pr_path(void){
    fprintf(fp_out, "%s", pp->path);
    return 0;
}

static int pr_name(void){
    char* tmp = strrchr(pp->path, '/');
    if (tmp && strlen(pp->cmd) >= 15)
	fprintf(fp_out, "%s", tmp + 1);
    else
	fprintf(fp_out, "%s", pp->cmd);
    return 0;
}

static int pr_parent(void){
    char tmp[1024];
    proc_cache_get(pp->ppid, tmp, sizeof tmp);
    fprintf(fp_out, "%s", tmp);
    return 0;
}

static int pr_processMD5(void) {
  fprintf(fp_out, "%s", "0");
  return 0;
}

static int pr_DigitalSign(void) {
  fprintf(fp_out, "%s", "0");
  return 0;
}

static int pr_Injection(void) {
  fprintf(fp_out, "%s", "0,0");
  return 0;
}

static int pr_Injected(void) {
  fprintf(fp_out, "%s", "0");
  return 0;
}

static int pr_AutoRun(void) {
  fprintf(fp_out, "%s", "0,0");
  return 0;
}

static int pr_Hide(void) {
  fprintf(fp_out, "%s", "0,0");
  return 0;
}

static int pr_ImportOtherDLL(void) {
  fprintf(fp_out, "%s", "null");
  return 0;
}

static int pr_Hook(void) {
  fprintf(fp_out, "%s", "null");
  return 0;
}

static int pr_ConnectIP(void) {
  fprintf(fp_out, "%s", "null");
  return 0;
}



/***************************************************************************/
/*************************** other stuff ***********************************/

static const format_struct format_array[] = {
/* code		print() */
{"autoRun",	pr_AutoRun},
{"c",		pr_c},
{"cmd",		pr_args},
{"connectIP",	pr_ConnectIP},
{"digitalsign",	pr_DigitalSign},
{"etime",	pr_etime},
{"hide",	pr_Hide},
{"hook",	pr_Hook},
{"importOtherDLL",	pr_ImportOtherDLL},
{"injected",	pr_Injected},
{"injection",	pr_Injection},
{"lstart",	pr_lstart},
{"name",	pr_name},
{"parent",	pr_parent},
{"path",	pr_path},
{"pid",		pr_pid},
{"ppid",	pr_ppid},
{"processMD5",	pr_processMD5},
{"stat",	pr_stat},
{"time",	pr_time},
{"timeout",	pr_timeout},
{"user",	pr_euser},
};



static const int format_array_count = sizeof(format_array)/sizeof(format_struct);

static int compare_format_structs(const void *a, const void *b){
  return strcmp(((const format_struct*)a)->spec,((const format_struct*)b)->spec);
}

const format_struct *search_format_array(const char *findme){
  format_struct key;
  key.spec = findme;
  return bsearch(&key, format_array, format_array_count,
    sizeof(format_struct), compare_format_structs
  );
}

/***************************************************************************/
/****************************** load format_list ***************************/

static format_node *do_one_spec(const char *spec){
  const format_struct *fs;

  fs = search_format_array(spec);
  if(fs){
    if (!strcmp(spec, "parent")) 
      need_record = 1;
    format_node *thisnode;
    thisnode = malloc(sizeof(format_node));
    thisnode->pr = fs->pr;
    thisnode->next = NULL;
    return thisnode;
  }
  return NULL;
}

const char *process_sf_options(const char *walk){
  format_list = NULL;

  format_node *fmt_walk;
  format_node *fn = NULL;

  if(!fn){
    format_node *newnode;
    int dist;
    char buf[16]; /* trust strings will be short (from above, not user) */
    //walk = "pid,ppid,user,lstart,cmd";
    while(*walk){
      printf("%s\n", walk);
      dist = strcspn(walk, ", ");
      strncpy(buf,walk,dist);
      buf[dist] = '\0';
      newnode = do_one_spec(buf); /* call self, assume success */
      newnode->next = fn;
      fn = newnode;
      walk += dist;
      if(*walk) walk++;
    }
  }

  fmt_walk = fn;
  while(fmt_walk){   /* put any nodes onto format_list in opposite way */
    format_node *travler;
    travler = fmt_walk;
    fmt_walk = fmt_walk->next;
    travler->next = format_list;
    format_list = travler;
  }

  return NULL;
}

void show_one_proc(proc_t* p){
  format_node *fmt = format_list;
  pp = p;
  for(;;){
    (*fmt->pr)();
    fmt = fmt->next;
    if(!fmt) break;
    fprintf(fp_out, "|");
  }
  fprintf(fp_out, "\n");
}

void show_later_one_proc(proc_t* p){
  struct proc_pr_later *newnode;
  newnode = malloc(sizeof(struct proc_pr_later));
  newnode->p = malloc(sizeof(proc_t));
  memcpy(newnode->p, p, sizeof(proc_t));
  (*newnode->p).cmdline = strvec_cpy((*p).cmdline);
  (*newnode->p).environ = strvec_cpy((*p).environ);
  newnode->next = proc_later_list;
  proc_later_list = newnode;
}

void print_show_later_list(void){
  struct proc_pr_later *ptr = proc_later_list;
  while (ptr) {
    show_one_proc(ptr->p);
    ptr = ptr->next;
  }
}

void init_output(void){
  seconds_since_boot    = uptime();
  seconds_since_1970	= time(NULL);
  time_of_boot		= seconds_since_1970 - seconds_since_boot;
}

void simple_spew(){
  proc_later_list = NULL;

  proc_t buf;
  PROCTAB* ptp = malloc(sizeof(PROCTAB));
  if (!ptp) {
     fprintf(stderr, "malloc failed");
     perror(NULL);
     exit(1);
  }
  if (!(ptp->procfs = opendir("/proc"))) {
    fprintf(stderr, "Error: can not access /proc.\n");
    exit(1);
  }
  memset(&buf, '#', sizeof(proc_t));
  while(ps_readproc(ptp,&buf)){
    if (need_record) {
      char* tmp = strrchr(buf.path, '/');
      if (tmp && strlen(buf.cmd) >= 15)
        proc_cache_add(buf.pid, tmp + 1, buf.start_time, buf.path);
      else
        proc_cache_add(buf.pid, buf.cmd, buf.start_time, buf.path);
    }
    if (need_record && buf.ppid != 0 && buf.pid < buf.ppid)
      show_later_one_proc(&buf);
    else
      show_one_proc(&buf);
    if(buf.cmdline) free((void*)*buf.cmdline); // ought to reuse
    if(buf.environ) free((void*)*buf.environ); // ought to reuse
  }
  closedir(ptp->procfs);
  free(ptp);

  print_show_later_list();
}





int my_ps(){
  init_output();
  fp_out = fopen("ps.txt", "w+");
  process_sf_options("name,lstart,cmd,processMD5,path,ppid,parent,digitalsign,pid,injection,injected,autoRun,hide,importOtherDLL,hook,connectIP");
  simple_spew();
  
  // if (argc > 1 && strcmp(opt, "All") == 0)
  //   process_sf_options("pid,ppid,name,lstart,parent,path,cmd,user");
  // else if (argc > 1 && strcmp(opt, "Info") == 0)
  //   process_sf_options("pid,lstart,path,cmd");		/* ProcessInfo */
  // else if (argc > 1 && strcmp(opt, "Main") == 0)
  //   process_sf_options("pid,ppid,name,lstart,parent");	/* MainProcess */
  // else if (argc > 1 && strcmp(opt, "Test") == 0)
  //   process_sf_options("c,cmd,etime,lstart,name,parent");	/* MainProcess */
  // else
  //   process_sf_options("pid,ppid,name,lstart,parent,path,cmd");

  

// {"name",	pr_name},
// {"time",	pr_time},
// {"cmd",		pr_args},
// {"processMD5",		pr_md5},
// {"path",	pr_path},
// {"parent",	pr_parent},



//   {"c",		pr_c},
// {"etime",	pr_etime},
// {"lstart",	pr_lstart},
// {"pid",		pr_pid},
// {"ppid",	pr_ppid},
// {"stat",	pr_stat},
// {"timeout",	pr_timeout},
// {"user",	pr_euser},

  /*unsigned long old_seconds_since_boot;
  while (1) { 
    old_seconds_since_boot = seconds_since_boot;
    init_output();
    if ((seconds_since_boot - old_seconds_since_boot) < 3){
      seconds_since_boot = old_seconds_since_boot;
      continue;
    }
    printf("%lu\n", seconds_since_boot);
    simple_spew();
  }*/
  return 0;
}


