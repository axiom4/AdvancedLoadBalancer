#define _GNU_SOURCE
#include "advlb/log.h"
#include "advlb/config.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <pthread.h>

static char s_log_ring[MAX_LOG_LINES][LOG_LINE_LEN] = {{0}};
static int s_log_head = 0;
static int s_log_total = 0;
static pthread_mutex_t s_log_mutex = PTHREAD_MUTEX_INITIALIZER;

void log_init(void) {
    pthread_mutex_lock(&s_log_mutex);
    memset(s_log_ring, 0, sizeof(s_log_ring));
    s_log_head = 0;
    s_log_total = 0;
    pthread_mutex_unlock(&s_log_mutex);
}

void add_log(const char *fmt, ...) {
    char time_str[32];
    time_t now = time(NULL);
    struct tm tm_buf;
    struct tm *tm_info = localtime_r(&now, &tm_buf);
    if (tm_info) {
        strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);
    } else {
        snprintf(time_str, sizeof(time_str), "00:00:00");
    }

    char msg[LOG_LINE_LEN];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);

    if (!g_config.enable_tui) {
        printf("[%s] %s\n", time_str, msg);
        fflush(stdout);
        return;
    }

    pthread_mutex_lock(&s_log_mutex);
    snprintf(s_log_ring[s_log_head], LOG_LINE_LEN, "[%s] %s", time_str, msg);
    s_log_head = (s_log_head + 1) % MAX_LOG_LINES;
    if (s_log_total < MAX_LOG_LINES) s_log_total++;
    pthread_mutex_unlock(&s_log_mutex);
}

int log_get_snapshot(char out_ring[MAX_LOG_LINES][LOG_LINE_LEN], int *out_total, int *out_head) {
    pthread_mutex_lock(&s_log_mutex);
    if (out_ring) {
        memcpy(out_ring, s_log_ring, sizeof(s_log_ring));
    }
    if (out_total) {
        *out_total = s_log_total;
    }
    if (out_head) {
        *out_head = s_log_head;
    }
    int total = s_log_total;
    pthread_mutex_unlock(&s_log_mutex);
    return total;
}

