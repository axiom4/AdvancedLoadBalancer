#ifndef ADVLB_CLI_H
#define ADVLB_CLI_H

#include <stdbool.h>
#include "advlb/types.h"

void print_help(const char *prog_name);
void parse_backend_arg(const char *arg);
bool parse_algorithm(const char *name, BalancerAlgorithm *out_alg);
bool parse_hc_type(const char *name, HealthCheckType *out_type);
int parse_cli_args(int argc, char *argv[]);

#endif /* ADVLB_CLI_H */

