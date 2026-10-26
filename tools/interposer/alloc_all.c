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

/* File offset of the ps_globals symbol inside libphp.so. Build-specific:
 * re-derive per target build with `nm /usr/lib/apache2/modules/libphp.so | grep -w ps_globals`
 * and pass -DPSG_OFF=0x... at compile time (default: php:8.5.11-apache). */
#ifndef PSG_OFF
#define PSG_OFF 0x01771a40ULL
#endif

static void ps_dump(void) {
    static unsigned last_id_type = 0xFFFFFFFFu, last_hs_type = 0xFFFFFFFFu;
    static unsigned long long last_id_ptr = 0, last_hs_ptr = 0;
    static int dbg = 0;
    init_log();
    if (!logf) return;
    unsigned long long base = get_libphp_base();
    if (dbg == 0) { dbg = 1; fprintf(logf, "DBG libphp_base=0x%llx psg_off=0x%llx\n", base, (unsigned long long)PSG_OFF); }
    if (!base) return;
    volatile char *psg = (volatile char *)(base + PSG_OFF);   /* &ps_globals */
    unsigned long long id_ptr = *(unsigned long long *)(psg + 16);
    unsigned long long hs_ref = *(unsigned long long *)(psg + 360);
    unsigned int hs_type = *(unsigned int *)(psg + 360 + 8);
    if (id_ptr != last_id_ptr) {
        /* Dump the OLD value's block content on every PS(id) change — this is
         * what a subsequent Set-Cookie emission would read from it. */
        if (last_id_ptr && last_id_ptr < 0x800000000000ULL) {
            volatile unsigned char *p = (volatile unsigned char *)last_id_ptr;
            fprintf(logf, "PS id=0x%llx old@0x%llx:", (unsigned long long)id_ptr,
                    (unsigned long long)last_id_ptr);
            for (int i = 0; i < 64; i++) fprintf(logf, "%02x", p[i]);
            fprintf(logf, "\n");
        } else {
            fprintf(logf, "PS id=0x%llx\n", (unsigned long long)id_ptr);
        }
        last_id_ptr = id_ptr; last_id_type = 0xFFFFFFFFu;
    }
    /* ---- stage-2 slot monitor -------------------------------------------
     * Watch the pDestructor slot of the per-part HashTable that lands at
     * PS(id)-0x10 (its +0x30 field == PS(id)+0x20, i.e. cookie byte 8..15).
     * Log every change with the full 56-byte table block so we can see WHEN
     * and AFTER WHICH ALLOCATION EVENT the value differs from zval_ptr_dtor.
     * Runs on every hooked call; only logs on change (cheap). */
    if (id_ptr && id_ptr < 0x800000000000ULL) {
        static unsigned long long last_slot = 0;
        static int slot_init = 0;
        volatile char *xb = (volatile char *)(id_ptr - 0x10);
        unsigned long long slotv = *(unsigned long long *)(id_ptr + 0x20);
        if (!slot_init || slotv != last_slot) {
            slot_init = 1; last_slot = slotv;
            fprintf(logf, "SLOT @0x%llx val=0x%llx rel=0x%llx block@PS-0x10:",
                    (unsigned long long)(id_ptr + 0x20), (unsigned long long)slotv,
                    base ? (unsigned long long)(slotv - base) : 0ULL);
            for (int i = 0; i < 56; i++) fprintf(logf, "%02x", xb[i]);
            fprintf(logf, "\n");
        }
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

/* ---- stage-2 write-source bisect: wrap session/URL-encode path ----------
 * Built to hunt a suspected pDestructor corruption on PHP 8.5.3 (the slot
 * appeared to hold zval_ptr_dtor+11). Verdict after the PRE/POST dumps below:
 * NOTHING corrupts anything — the slot holds exactly zval_ptr_dtor at read
 * time, and php_url_encode's input already contains the exact pointer bytes.
 * The apparent +11 was a client-side cookie-decode bug: this build's dtor
 * offset ends in 0x20 (space), which php_url_encode emits as '+', and our
 * parser left '+' undecoded. Kept for future slot/encoder forensics. */
static unsigned long long slot_now(void) {
    unsigned long long base = get_libphp_base();
    if (!base) return 0;
    volatile char *psg = (volatile char *)(base + PSG_OFF);
    unsigned long long id_ptr = *(unsigned long long *)(psg + 16);
    if (!id_ptr || id_ptr >= 0x800000000000ULL) return 0;
    return *(unsigned long long *)(id_ptr + 0x20);
}

void *php_url_encode(const char *str, size_t len) {
    static void *(*real)(const char *, size_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "php_url_encode");
    init_log(); ps_dump();
    if (logf) {
        fprintf(logf, "PRE urlenc str=%p len=%zu slot=0x%llx in16:",
                (void *)str, len, slot_now());
        for (size_t i = 0; i < len && i < 16; i++) fprintf(logf, "%02x", (unsigned char)str[i]);
        if (len > 16) fprintf(logf, "...");
        fprintf(logf, "\n");
    }
    void *r = real(str, len);
    if (logf && r) {
        /* zend_string: gc@0(8B), h@8(u64), len@16(u64), val@24 */
        unsigned long long elen = *(unsigned long long *)((char *)r + 16);
        volatile unsigned char *ev = (volatile unsigned char *)r + 24;
        fprintf(logf, "POST urlenc result len=%llu bytes:", (unsigned long long)elen);
        for (unsigned long long i = 0; i < elen && i < 60; i++) fprintf(logf, "%02x", ev[i]);
        fprintf(logf, "\n");
    }
    return r;
}

int php_session_reset_id(void) {
    static int (*real)(void) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "php_session_reset_id");
    init_log(); ps_dump();
    if (logf) fprintf(logf, "PRE reset_id slot=0x%llx\n", slot_now());
    int r = real();
    if (logf) fprintf(logf, "POST reset_id rc=%d slot=0x%llx\n", r, slot_now());
    return r;
}
