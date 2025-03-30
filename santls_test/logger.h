#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>


int logger_init(const char *filename, int is_enabled);


int log_printf(const char *format, ...);


void logger_close(void);

#endif 