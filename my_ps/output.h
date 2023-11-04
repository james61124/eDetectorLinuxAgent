#include "proc/readproc.h"
#include "proc/sysinfo.h"

#include <unordered_map>
#include <string>
#include <cstring>

#define PROC_HASH_SIZE 256
#define PROC_HASHIT(x) ((x) % PROC_HASH_SIZE)

class Process {
public:
    Process();

    typedef struct {
        int pid;
    } process;

    typedef struct format_node {
        struct format_node *next;
        int (Process:: *pr)(void);                         /* print function */
    } format_node;

    typedef struct format_struct {
        const char *spec; /* format specifier */
        int (Process:: *pr)(void); /* print function */
    } format_struct;

    struct proc_node {
        struct proc_node *next;
        int pid;
        char name[32];
        unsigned long time;
        char path[512];
    } *proc_hash[PROC_HASH_SIZE];

    struct proc_pr_later {
        struct proc_pr_later *next;
        proc_t *p;
    } *proc_later_list;

    typedef struct ProcessInfo_ {
        int pid;
        int ppid;
        char process_name[16];
        unsigned long long start_time;
        char parent_process_name[16];
        unsigned long long  parent_start_time;
        char path[1024];
        char username[16];

    } ProcessInfo;
    std::unordered_map<int, ProcessInfo>ProcessInfoMap;

    proc_t *pp;     /* the process being printed */

    unsigned long seconds_since_boot = -1;
    unsigned long seconds_since_1970;
    unsigned long time_of_boot;
    int need_record = 0;

    format_node *format_list = (format_node *)0xdeadbeef;
    const format_struct format_array[22] = {
        /* code		print() */
        {"autoRun",	&Process::pr_AutoRun},
        {"c",		&Process::pr_c},
        {"cmd",		&Process::pr_args},
        {"connectIP",	&Process::pr_ConnectIP},
        {"digitalsign",	&Process::pr_DigitalSign},
        {"etime",	&Process::pr_etime},
        {"hide",	&Process::pr_Hide},
        {"hook",	&Process::pr_Hook},
        {"importOtherDLL",	&Process::pr_ImportOtherDLL},
        {"injected",	&Process::pr_Injected},
        {"injection",	&Process::pr_Injection},
        {"lstart",	&Process::pr_lstart},
        {"name",	&Process::pr_name},
        {"parent",	&Process::pr_parent},
        {"path",	&Process::pr_path},
        {"pid",		&Process::pr_pid},
        {"ppid",	&Process::pr_ppid},
        {"processMD5",	&Process::pr_processMD5},
        {"stat",	&Process::pr_stat},
        {"time",	&Process::pr_time},
        {"timeout",	&Process::pr_timeout},
        {"user",	&Process::pr_euser},
       
        
    
    };
    const int format_array_count = sizeof(format_array)/sizeof(format_struct);

    FILE * fp_out;

    // format_struct* format_array;
    // const int format_array_count = sizeof(format_array)/sizeof(format_struct);

    int simple_escape_str(char *dst, const char *src, size_t n);
    char** strvec_cpy(char** cmdline);
    void proc_cache_add(int pid, char *name, unsigned long long time, char* path);
    void proc_cache_get(int pid, char *ret, int retSize);
    int pr_args(void);
    int pr_etime(void);
    int pr_c(void);
    int pr_pid(void);
    int pr_ppid(void);
    int pr_time(void);
    int pr_euser(void);
    int pr_stat(void);
    int old_time_helper(unsigned long long t, unsigned long long rel);
    int pr_timeout(void);
    int pr_lstart(void);
    int pr_path(void);
    int pr_name(void);
    int pr_parent(void);
    int pr_processMD5(void);
    int pr_DigitalSign(void);
    int pr_Injection(void);
    int pr_Injected(void);
    int pr_AutoRun(void);
    int pr_Hide(void);
    int pr_ImportOtherDLL(void);
    int pr_Hook(void);
    int pr_ConnectIP(void);

    static int compare_format_structs(const void *a, const void *b);
    const format_struct *search_format_array(const char *findme);
    format_node *do_one_spec(const char *spec);
    const char *process_sf_options(const char *walk);
    void show_one_proc(proc_t* p);
    void show_later_one_proc(proc_t* p);
    void print_show_later_list(void);
    void init_output(void);
    void simple_spew();
    int my_ps();

};

