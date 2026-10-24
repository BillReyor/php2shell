/* alloc_trace.c — LD_PRELOAD interposer for PHP memory API (PHP 8.x exports
 * with underscore prefix: _emalloc, _erealloc, ...).
 * Logs large allocations and ALL failures (NULL returns) with backtraces.
 * Build: gcc -shared -fPIC -O1 -o alloc_trace.so alloc_trace.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static FILE *logf = NULL;
static void init_log(void) {
    if (!logf) {
        const char *p = getenv("ALLOC_LOG");
        logf = fopen(p ? p : "/tmp/alloc.log", "a");
        if (logf) setvbuf(logf, NULL, _IOLBF, 0);
    }
}

static void bt(FILE *f) {
    void *frames[14];
    int n = backtrace(frames, 14);
    for (int i = 0; i < n; i++) fprintf(f, " #%d %p", i, frames[i]);
    fprintf(f, "\n");
}

void *_emalloc(size_t size) {
    static void *(*real)(size_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "_emalloc");
    init_log();
    void *r = real(size);
    if (logf && (size >= 4096 || r == NULL)) {
        fprintf(logf, "EMALLOC size=%zu ret=%p%s", size, r, r ? "" : "  <-- FAIL");
        bt(logf); fflush(logf);
    }
    return r;
}

void *_erealloc(void *ptr, size_t size) {
    static void *(*real)(void *, size_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "_erealloc");
    init_log();
    void *r = real(ptr, size);
    if (logf && (size >= 4096 || r == NULL)) {
        fprintf(logf, "EREALLOC from=%p size=%zu ret=%p%s", ptr, size, r, r ? "" : "  <-- FAIL");
        bt(logf); fflush(logf);
    }
    return r;
}

void *_efree(void *ptr) {
    static void (*real)(void *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "_efree");
    real(ptr);
}

char *_estrdup(const char *s) {
    static char *(*real)(const char *) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "_estrdup");
    init_log();
    size_t len = s ? strlen(s) : 0;
    char *r = real(s);
    if (logf && (len >= 4096 || r == NULL)) {
        fprintf(logf, "ESTRDUP len=%zu ret=%p%s", len, r, r ? "" : "  <-- FAIL");
        bt(logf); fflush(logf);
    }
    return r;
}

char *_estrndup(const char *s, size_t len) {
    static char *(*real)(const char *, size_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "_estrndup");
    init_log();
    char *r = real(s, len);
    if (logf && (len >= 4096 || r == NULL)) {
        fprintf(logf, "ESTRNDUP len=%zu ret=%p%s", len, r, r ? "" : "  <-- FAIL");
        bt(logf); fflush(logf);
    }
    return r;
}

void *_safe_emalloc(size_t nmemb, size_t size, size_t offset) {
    static void *(*real)(size_t, size_t, size_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "_safe_emalloc");
    init_log();
    size_t total = nmemb * (size + offset);
    void *r = real(nmemb, size, offset);
    if (logf && (total >= 4096 || r == NULL)) {
        fprintf(logf, "SAFE_EMALLOC n=%zu sz=%zu off=%zu total=%zu ret=%p%s", nmemb, size, offset, total, r, r ? "" : "  <-- FAIL");
        bt(logf); fflush(logf);
    }
    return r;
}

void *_safe_erealloc(void *ptr, size_t nmemb, size_t size, size_t offset) {
    static void *(*real)(void *, size_t, size_t, size_t) = NULL;
    if (!real) real = dlsym(RTLD_NEXT, "_safe_erealloc");
    init_log();
    size_t total = nmemb * (size + offset);
    void *r = real(ptr, nmemb, size, offset);
    if (logf && (total >= 4096 || r == NULL)) {
        fprintf(logf, "SAFE_EREALLOC from=%p n=%zu sz=%zu off=%zu total=%zu ret=%p%s", ptr, nmemb, size, offset, total, r, r ? "" : "  <-- FAIL");
        bt(logf); fflush(logf);
    }
    return r;
}
