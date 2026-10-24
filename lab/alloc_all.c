/* alloc_all.c — LD_PRELOAD: log PHP memory API calls AND track PS() session-globals changes. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FILE *logf = NULL;
static void init_log(void) {
    if (!logf) {
        logf = fopen("/tmp/alloc_all.log", "a");
        if (logf) setvbuf(logf, NULL, _IOLBF, 0);
    }
}

/* ---- PS() session-globals reader ---------------------------------------- */
/* ps_globals is a by-value struct in libphp.so BSS at offset 0x01771a40.
   Offsets (from offsetof vs real headers): id=16, mod_data=96, send_cookie=350,
   http_session_vars=360. A zval = { union(8B) ; uint32 value_type @ +8 }. */
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
    /* PS(id): zend_string* at offset 16 */
    unsigned long long id_ptr = *(unsigned long long *)(psg + 16);
    /* PS(http_session_vars): zval at offset 360 -> referent @+0, value_type @+8 */
    unsigned long long hs_ref = *(unsigned long long *)(psg + 360);
    unsigned int hs_type = *(unsigned int *)(psg + 360 + 8);
    if (id_ptr != last_id_ptr) {
        fprintf(logf, "PS id=0x%llx\n", (unsigned long long)id_ptr);
        last_id_ptr = id_ptr; last_id_type = 0xFFFFFFFFu; /* reset hs tracking on id change */
    }
    if (hs_ref != last_hs_ptr || hs_type != last_hs_type) {
        fprintf(logf, "PS http_session_vars type=%u ref=0x%llx\n", hs_type, (unsigned long long)hs_ref);
        last_hs_ptr = hs_ref; last_hs_type = hs_type;
    }
}

/* ---- memory API interposition ------------------------------------------- */
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
