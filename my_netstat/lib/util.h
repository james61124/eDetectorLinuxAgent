#ifndef UTIL_H
#define UTIL_H

void *xmalloc(size_t sz);
char *xstrdup(const char *src);
long ticks_per_second(void);
char *safe_strncpy(char *dst, const char *src, size_t size);

#define netmin(a,b) ((a)<(b) ? (a) : (b))
#define netmax(a,b) ((a)>(b) ? (a) : (b))

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#endif // UTIL_H
