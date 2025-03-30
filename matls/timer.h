#include <stdio.h>
#include <time.h>

// Define a Timer structure to store start and end times.
typedef struct {
    struct timespec start;
    struct timespec end;
} Timer;

void start_timer(Timer *timer) {
    clock_gettime(CLOCK_MONOTONIC, &timer->start);
}

// Stops the timer and returns the elapsed time in milliseconds.
double stop_timer(Timer *timer) {
    clock_gettime(CLOCK_MONOTONIC, &timer->end);
    double elapsed_ms = (timer->end.tv_sec - timer->start.tv_sec) * 1000.0;
    elapsed_ms += (timer->end.tv_nsec - timer->start.tv_nsec) / 1000000.0;
    return elapsed_ms;
}
