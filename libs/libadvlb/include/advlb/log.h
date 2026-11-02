#ifndef ADVLB_LOG_H
#define ADVLB_LOG_H

#include <stddef.h>
#include "advlb/types.h"

void log_init(void);
void add_log(const char *fmt, ...);
int log_get_snapshot(char out_ring[MAX_LOG_LINES][LOG_LINE_LEN], int *out_total, int *out_head);

#endif /* ADVLB_LOG_H */

