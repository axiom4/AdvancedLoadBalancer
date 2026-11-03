#define _GNU_SOURCE
#include "advlb/log.h"
#include "advlb/config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>

#define ASYNC_LOG_QUEUE_SIZE 4096
#define ASYNC_LOG_QUEUE_MASK (ASYNC_LOG_QUEUE_SIZE - 1)

typedef struct {
    atomic_uint sequence;
    char text[LOG_LINE_LEN];
} LogCell;

static LogCell s_queue[ASYNC_LOG_QUEUE_SIZE];
static atomic_uint s_enqueue_pos;
static unsigned int s_dequeue_pos = 0;

static char s_log_ring[MAX_LOG_LINES][LOG_LINE_LEN] = {{0}};
static int s_log_head = 0;
static int s_log_total = 0;
static pthread_mutex_t s_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static pthread_t s_drain_tid;
static atomic_bool s_drain_running = false;
static atomic_bool s_drain_waiting = false;
static atomic_uint s_dropped_logs = 0;
static pthread_mutex_t s_drain_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t s_drain_cond = PTHREAD_COND_INITIALIZER;

// Lock-Free Bounded MPSC Enqueue
static bool mpsc_enqueue(const char *msg) {
    unsigned int pos = atomic_load_explicit(&s_enqueue_pos, memory_order_relaxed);
    for (;;) {
        LogCell *cell = &s_queue[pos & ASYNC_LOG_QUEUE_MASK];
        unsigned int seq = atomic_load_explicit(&cell->sequence, memory_order_acquire);
        int diff = (int)(seq - pos);
        if (diff == 0) {
            if (atomic_compare_exchange_weak_explicit(&s_enqueue_pos, &pos, pos + 1,
                                                      memory_order_relaxed, memory_order_relaxed)) {
                size_t len = strlen(msg);
                if (len >= LOG_LINE_LEN) len = LOG_LINE_LEN - 1;
                memcpy(cell->text, msg, len);
                cell->text[len] = '\0';
                atomic_store_explicit(&cell->sequence, pos + 1, memory_order_release);
                return true;
            }
        } else if (diff < 0) {
            // Queue is full
            return false;
        } else {
            pos = atomic_load_explicit(&s_enqueue_pos, memory_order_relaxed);
        }
    }
}

// Single-Consumer Dequeue
static bool mpsc_dequeue(char *out_msg, size_t max_len) {
    LogCell *cell = &s_queue[s_dequeue_pos & ASYNC_LOG_QUEUE_MASK];
    unsigned int seq = atomic_load_explicit(&cell->sequence, memory_order_acquire);
    int diff = (int)(seq - (s_dequeue_pos + 1));
    if (diff == 0) {
        size_t len = strlen(cell->text);
        if (len >= max_len) len = max_len - 1;
        memcpy(out_msg, cell->text, len);
        out_msg[len] = '\0';
        atomic_store_explicit(&cell->sequence, s_dequeue_pos + ASYNC_LOG_QUEUE_SIZE, memory_order_release);
        s_dequeue_pos++;
        return true;
    }
    return false;
}

static void process_drained_log(const char *line) {
    if (!g_config.enable_tui) {
        fputs(line, stdout);
        fputc('\n', stdout);
    }

    pthread_mutex_lock(&s_log_mutex);
    snprintf(s_log_ring[s_log_head], LOG_LINE_LEN, "%s", line);
    s_log_head = (s_log_head + 1) % MAX_LOG_LINES;
    if (s_log_total < MAX_LOG_LINES) s_log_total++;
    pthread_mutex_unlock(&s_log_mutex);
}

static void *log_drain_worker(void *arg) {
    (void)arg;
    char msg[LOG_LINE_LEN];

    while (atomic_load_explicit(&s_drain_running, memory_order_relaxed)) {
        bool drained_any = false;
        int batch_count = 0;

        while (mpsc_dequeue(msg, sizeof(msg))) {
            drained_any = true;
            batch_count++;
            process_drained_log(msg);
            if (!g_config.enable_tui && (batch_count % 64 == 0)) {
                fflush(stdout);
            }
        }

        if (!g_config.enable_tui && batch_count > 0) {
            fflush(stdout);
        }

        unsigned int dropped = atomic_exchange_explicit(&s_dropped_logs, 0, memory_order_relaxed);
        if (dropped > 0) {
            char drop_warn[LOG_LINE_LEN];
            snprintf(drop_warn, sizeof(drop_warn), "\033[1;33m[WARNING]\033[0m Ring-buffer dropped %u log messages during burst", dropped);
            process_drained_log(drop_warn);
            if (!g_config.enable_tui) fflush(stdout);
        }

        if (!drained_any && atomic_load_explicit(&s_drain_running, memory_order_relaxed)) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_nsec += 20000000; // 20ms timeout
            if (ts.tv_nsec >= 1000000000) {
                ts.tv_sec += 1;
                ts.tv_nsec -= 1000000000;
            }

            pthread_mutex_lock(&s_drain_mutex);
            atomic_store_explicit(&s_drain_waiting, true, memory_order_relaxed);
            // Re-check queue before sleeping to prevent race conditions
            LogCell *peek_cell = &s_queue[s_dequeue_pos & ASYNC_LOG_QUEUE_MASK];
            unsigned int seq = atomic_load_explicit(&peek_cell->sequence, memory_order_acquire);
            if ((int)(seq - (s_dequeue_pos + 1)) != 0 && atomic_load_explicit(&s_drain_running, memory_order_relaxed)) {
                pthread_cond_timedwait(&s_drain_cond, &s_drain_mutex, &ts);
            }
            atomic_store_explicit(&s_drain_waiting, false, memory_order_relaxed);
            pthread_mutex_unlock(&s_drain_mutex);
        }
    }

    // Final drain of any remaining messages
    int final_batch = 0;
    while (mpsc_dequeue(msg, sizeof(msg))) {
        final_batch++;
        process_drained_log(msg);
    }
    if (!g_config.enable_tui && final_batch > 0) {
        fflush(stdout);
    }
    return NULL;
}

void log_init(void) {
    if (atomic_load_explicit(&s_drain_running, memory_order_relaxed)) {
        return;
    }

    pthread_mutex_lock(&s_log_mutex);
    memset(s_log_ring, 0, sizeof(s_log_ring));
    s_log_head = 0;
    s_log_total = 0;
    pthread_mutex_unlock(&s_log_mutex);

    for (unsigned int i = 0; i < ASYNC_LOG_QUEUE_SIZE; i++) {
        atomic_init(&s_queue[i].sequence, i);
    }
    atomic_init(&s_enqueue_pos, 0);
    s_dequeue_pos = 0;
    atomic_init(&s_dropped_logs, 0);
    atomic_init(&s_drain_waiting, false);

    atomic_store_explicit(&s_drain_running, true, memory_order_release);
    if (pthread_create(&s_drain_tid, NULL, log_drain_worker, NULL) != 0) {
        atomic_store_explicit(&s_drain_running, false, memory_order_relaxed);
    }
}

void log_shutdown(void) {
    if (!atomic_load_explicit(&s_drain_running, memory_order_relaxed)) {
        return;
    }

    atomic_store_explicit(&s_drain_running, false, memory_order_release);

    pthread_mutex_lock(&s_drain_mutex);
    pthread_cond_signal(&s_drain_cond);
    pthread_mutex_unlock(&s_drain_mutex);

    pthread_join(s_drain_tid, NULL);
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

    char full_line[LOG_LINE_LEN];
    int pfx_len = snprintf(full_line, sizeof(full_line), "[%s] ", time_str);
    if (pfx_len > 0 && (size_t)pfx_len < sizeof(full_line)) {
        va_list args;
        va_start(args, fmt);
        vsnprintf(full_line + pfx_len, sizeof(full_line) - (size_t)pfx_len, fmt, args);
        va_end(args);
    } else {
        full_line[0] = '\0';
    }

    if (!atomic_load_explicit(&s_drain_running, memory_order_relaxed)) {
        if (!g_config.enable_tui) {
            printf("%s\n", full_line);
            fflush(stdout);
            return;
        }
        pthread_mutex_lock(&s_log_mutex);
        snprintf(s_log_ring[s_log_head], LOG_LINE_LEN, "%s", full_line);
        s_log_head = (s_log_head + 1) % MAX_LOG_LINES;
        if (s_log_total < MAX_LOG_LINES) s_log_total++;
        pthread_mutex_unlock(&s_log_mutex);
        return;
    }

    if (!mpsc_enqueue(full_line)) {
        atomic_fetch_add_explicit(&s_dropped_logs, 1, memory_order_relaxed);
    }

    if (atomic_load_explicit(&s_drain_waiting, memory_order_relaxed)) {
        pthread_mutex_lock(&s_drain_mutex);
        pthread_cond_signal(&s_drain_cond);
        pthread_mutex_unlock(&s_drain_mutex);
    }
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
