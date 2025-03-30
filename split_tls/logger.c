#include "logger.h"
#include <stdarg.h>
#include <stdlib.h>

static FILE *log_file = NULL;
int should_log = 1;

int logger_init(const char *filename, int is_enabled) {
    if (filename == NULL) {
        fprintf(stderr, "Unable to open file");
        return -1;
    }
    should_log = is_enabled;
    log_file = fopen(filename, "w"); 
    if (log_file == NULL) {

        return -1;
    }
    
    return 0;
}

int log_printf(const char *format, ...) {

    if(should_log == 0){
        return -1;
    }
    if (log_file == NULL) {
        return -1; 
    }
    
    va_list args;
    va_start(args, format);
    int ret = vfprintf(log_file, format, args);
    va_end(args);
    
    fflush(log_file); 
    return ret;
}

void logger_close(void) {
    if (log_file != NULL) {
        fclose(log_file);
        log_file = NULL;
    }
}