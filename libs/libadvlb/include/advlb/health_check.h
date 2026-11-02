#ifndef ADVLB_HEALTH_CHECK_H
#define ADVLB_HEALTH_CHECK_H

#include <stdbool.h>
#include "advlb/types.h"

const char *health_check_name(HealthCheckType type);
void finalize_payload_config(void);
void perform_health_check_cycle(bool is_startup);
void *health_check_thread(void *arg);

#endif /* ADVLB_HEALTH_CHECK_H */

