#ifndef ADVLB_TUI_H
#define ADVLB_TUI_H

#include <stdbool.h>

#define CP_HEADER   1
#define CP_CYAN     2
#define CP_GREEN    3
#define CP_RED      4
#define CP_YELLOW   5
#define CP_MAGENTA  6
#define CP_BLUE     7
#define CP_FOOTER   8
#define CP_BTN_NO   9
#define CP_BTN_YES  10

void init_tui(void);
void cleanup_tui(void);
void handle_signal(int sig);
void render_tui(void);
void *tui_thread(void *arg);
void print_log_line_ncurses(int y, int target_w, const char *line);

#endif /* ADVLB_TUI_H */

