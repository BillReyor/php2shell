/* alloc_all.c v2 — LD_PRELOAD: log PHP memory API calls (INCLUDING the PHP 8.5
 * size-specialized _emalloc_<N>/_efree_<N> variants that carry nearly all small
 * allocations) AND track PS() session-globals changes.
 *
 * PHP 8.5 zend_alloc exports per-size wrappers: _emalloc_8..3072 (no-arg, return ptr)
 * and _efree_8..3072 (ptr arg). The generic _emalloc/_efree are only used for sizes
 * outside that set — hooking only the generics misses ~all request-time small allocs.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static FILE *logf = NULL;
static void init_log(void) {
    if (!logf) {
        logf = fopen("/tmp/alloc_all.log", "a");
        if (logf) setvbuf(logf, NULL, _IOLBF, 65536); /* line-buffered, explicit size */
    }
}

/* ---- PS() session-globals reader ---------------------------------------- */
static unsigned long long get_libphp_base(void) {
    static unsigned long long base = 0;
    if (base) return base;
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    while (fgets(line, sizeof line, f)) {
        if (strstr(line, "libphp.so")) { base = strtoull(line, NULL, 16); break; }
    }
    fclose(f);
    return base;
}

static void ps_dump(void) {
    static unsigned last_id_type = 0xFFFFFFFFu, last_hs_type = 0xFFFFFFFFu;
    static unsigned long long last_id_ptr = 0, last_hs_ptr = 0;
    static int dbg = 0;
    init_log();
    if (!logf) return;
    unsigned long long base = get_libphp_base();
    if (dbg == 0) { dbg = 1; fprintf(logf, "DBG libphp_base=0x%llx\n", base); }
    if (!base) return;
    volatile char *psg = (volatile char *)(base + 0x01771a40);   /* &ps_globals */
    unsigned long long id_ptr = *(unsigned long long *)(psg + 16);
    unsigned long long hs_ref = *(unsigned long long *)(psg + 360);
    unsigned int hs_type = *(unsigned int *)(psg + 360 + 8);
    if (id_ptr != last_id_ptr) {
        fprintf(logf, "PS id=0x%llx\n", (unsigned long long)id_ptr);
        last_id_ptr = id_ptr; last_id_type = 0xFFFFFFFFu;
    }
    if (hs_ref != last_hs_ptr || hs_type != last_hs_type) {
        fprintf(logf, "PS http_session_vars type=%u ref=0x%llx\n", hs_type, (unsigned long long)hs_ref);
        last_hs_ptr = hs_ref; last_hs_type = hs_type;
    }
}

/* ---- generic memory API interposition ------------------------------------ */
void *_emalloc(size_t size) {
    static void *(*real)(size_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "_emalloc");
    init_log(); ps_dump();
    void *r = real(size);
    if (logf) fprintf(logf, "M %zu %p\n", size, r);
    return r;
}

void *_erealloc(void *ptr, size_t size) {
    static void *(*real)(void *, size_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "_erealloc");
    init_log(); ps_dump();
    void *r = real(ptr, size);
    if (logf) fprintf(logf, "R %p %zu %p\n", ptr, size, r);
    return r;
}

void *_efree(void *ptr) {
    static void (*real)(void *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "_efree");
    init_log(); ps_dump();
    if (logf) fprintf(logf, "F %p\n", ptr);
    real(ptr);
}

char *_estrdup(const char *s) {
    static char *(*real)(const char *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "_estrdup");
    init_log(); ps_dump();
    size_t len = s ? strlen(s) : 0;
    char *r = real(s);
    if (logf) fprintf(logf, "S %zu %p\n", len, r);
    return r;
}

char *_estrndup(const char *s, size_t len) {
    static char *(*real)(const char *, size_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "_estrndup");
    init_log(); ps_dump();
    char *r = real(s, len);
    if (logf) fprintf(logf, "S %zu %p\n", len, r);
    return r;
}

void *_safe_emalloc(size_t nmemb, size_t size, size_t offset) {
    static void *(*real)(size_t, size_t, size_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "_safe_emalloc");
    init_log(); ps_dump();
    void *r = real(nmemb, size, offset);
    if (logf) fprintf(logf, "M %zu %p\n", nmemb * (size + offset), r);
    return r;
}

void *_safe_erealloc(void *ptr, size_t nmemb, size_t size, size_t offset) {
    static void *(*real)(void *, size_t, size_t, size_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "_safe_erealloc");
    init_log(); ps_dump();
    void *r = real(ptr, nmemb, size, offset);
    if (logf) fprintf(logf, "R %p %zu %p\n", ptr, nmemb * (size + offset), r);
    return r;
}

/* ---- PHP 8.5 size-specialized variants ------------------------------------ */
#define HOOK_EMALLOC(SZ) \
void *_emalloc_##SZ(void) { \
    static void *(*real)(void) = NULL; \
    if (!real) real = dlsym(RTLD_NEXT, "_emalloc_" #SZ); \
    init_log(); ps_dump(); \
    void *r = real(); \
    if (logf) fprintf(logf, "M %d %p\n", SZ, r); \
    return r; \
}

#define HOOK_EFREE(SZ) \
void _efree_##SZ(void *ptr) { \
    static void (*real)(void *) = NULL; \
    if (!real) real = dlsym(RTLD_NEXT, "_efree_" #SZ); \
    init_log(); ps_dump(); \
    if (logf) fprintf(logf, "F %p\n", ptr); \
    real(ptr); \
}

HOOK_EMALLOC(8)   HOOK_EFREE(8)
HOOK_EMALLOC(16)  HOOK_EFREE(16)
HOOK_EMALLOC(24)  HOOK_EFREE(24)
HOOK_EMALLOC(32)  HOOK_EFREE(32)
HOOK_EMALLOC(40)  HOOK_EFREE(40)
HOOK_EMALLOC(48)  HOOK_EFREE(48)
HOOK_EMALLOC(56)  HOOK_EFREE(56)
HOOK_EMALLOC(64)  HOOK_EFREE(64)
HOOK_EMALLOC(80)  HOOK_EFREE(80)
HOOK_EMALLOC(96)  HOOK_EFREE(96)
HOOK_EMALLOC(112) HOOK_EFREE(112)
HOOK_EMALLOC(128) HOOK_EFREE(128)
HOOK_EMALLOC(160) HOOK_EFREE(160)
HOOK_EMALLOC(192) HOOK_EFREE(192)
HOOK_EMALLOC(224) HOOK_EFREE(224)
HOOK_EMALLOC(256) HOOK_EFREE(256)
HOOK_EMALLOC(320) HOOK_EFREE(320)
HOOK_EMALLOC(384) HOOK_EFREE(384)
HOOK_EMALLOC(448) HOOK_EFREE(448)
HOOK_EMALLOC(512) HOOK_EFREE(512)
HOOK_EMALLOC(640) HOOK_EFREE(640)
HOOK_EMALLOC(768) HOOK_EFREE(768)
HOOK_EMALLOC(896) HOOK_EFREE(896)
HOOK_EMALLOC(1024)  HOOK_EFREE(1024)
HOOK_EMALLOC(1280)  HOOK_EFREE(1280)
HOOK_EMALLOC(1536)  HOOK_EFREE(1536)
HOOK_EMALLOC(1792)  HOOK_EFREE(1792)
HOOK_EMALLOC(2048)  HOOK_EFREE(2048)
HOOK_EMALLOC(2560)  HOOK_EFREE(2560)
HOOK_EMALLOC(3072)  HOOK_EFREE(3072)
