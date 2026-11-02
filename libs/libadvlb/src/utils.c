#define _GNU_SOURCE
#include "advlb/utils.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

int visible_len(const char *s) {
    if (!s) return 0;
    int v = 0;
    bool in_esc = false;
    mbstate_t ps;
    memset(&ps, 0, sizeof(ps));

    size_t s_len = strlen(s);
    for (size_t i = 0; i < s_len; ) {
        if (s[i] == '\033') {
            in_esc = true;
            i++;
        } else if (in_esc) {
            // ANSI escape sequences typically terminate with an alpha character (e.g. 'm' for colors)
            if ((s[i] >= 'A' && s[i] <= 'Z') || (s[i] >= 'a' && s[i] <= 'z')) {
                in_esc = false;
            }
            i++;
        } else {
            wchar_t wc = 0;
            size_t remaining = s_len - i;
            size_t len = mbrtowc(&wc, &s[i], remaining, &ps);
            if (len == 0) {
                // Null character encountered
                break;
            } else if (len == (size_t)-1 || len == (size_t)-2) {
                // Invalid or incomplete multibyte sequence: count 1 byte and reset shift state
                v++;
                i++;
                memset(&ps, 0, sizeof(ps));
            } else {
                int w = wcwidth(wc);
                v += (w >= 0) ? w : 1;
                i += len;
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

