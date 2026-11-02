#define _GNU_SOURCE
#include "advlb/utils.h"
#include <stdbool.h>
#include <stdlib.h>
#include <wchar.h>

int visible_len(const char *s) {
    if (!s) return 0;
    int v = 0;
    bool in_esc = false;
    mbtowc(NULL, NULL, 0);

    for (int i = 0; s[i] != '\0'; ) {
        if (s[i] == '\033') {
            in_esc = true;
            i++;
        } else if (in_esc) {
            if (s[i] == 'm') in_esc = false;
            i++;
        } else {
            wchar_t wc;
            int len = mbtowc(&wc, &s[i], MB_CUR_MAX);
            if (len > 0) {
                int w = wcwidth(wc);
                v += (w >= 0) ? w : 1;
                i += len;
            } else {
                v++;
                i++;
            }
        }
    }
    return v;
}

void unescape_string(char *dest, const char *src, size_t max_len) {
    if (!dest || !src || max_len == 0) return;
    size_t d = 0;
    for (size_t s = 0; src[s] != '\0' && d + 1 < max_len; s++) {
        if (src[s] == '\\' && src[s + 1] != '\0') {
            s++;
            switch (src[s]) {
                case 'r': dest[d++] = '\r'; break;
                case 'n': dest[d++] = '\n'; break;
                case 't': dest[d++] = '\t'; break;
                case '\\': dest[d++] = '\\'; break;
                case '0': dest[d++] = '\0'; break;
                default:
                    dest[d++] = '\\';
                    if (d + 1 < max_len) dest[d++] = src[s];
                    break;
            }
        } else {
            dest[d++] = src[s];
        }
    }
    dest[d] = '\0';
}

