#ifndef ADVLB_UTILS_H
#define ADVLB_UTILS_H

#include <stddef.h>

int visible_len(const char *s);
void unescape_string(char *dest, const char *src, size_t max_len);

#endif /* ADVLB_UTILS_H */

