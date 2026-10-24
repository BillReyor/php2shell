#include <stdio.h>
__attribute__((constructor)) static void mark(void){FILE*f=fopen("/tmp/preload_marker.txt","a");if(f){fputs("LOADED\n",f);fclose(f);}}
