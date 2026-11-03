#define _GNU_SOURCE
#include "advlb/tui.h"
#include "advlb/balancer.h"
#include "advlb/config.h"
#include "advlb/health_check.h"
#include "advlb/log.h"
#include "advlb/utils.h"
#include "advlb/cluster.h"
#include "advlb/session_table.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>
#include <ncurses.h>

static bool s_term_raw_enabled = false;

void init_tui(void) {
    if (!g_config.enable_tui || !isatty(STDIN_FILENO)) {
        g_config.enable_tui = false;
        return;
    }

    setlocale(LC_ALL, "");
    initscr();
    raw();
    noecho();
    nodelay(stdscr, TRUE);
    keypad(stdscr, TRUE);
    curs_set(0);

    if (has_colors()) {
        start_color();
        use_default_colors();
        init_pair(CP_HEADER, COLOR_WHITE, COLOR_BLUE);
        init_pair(CP_CYAN, COLOR_CYAN, -1);
        init_pair(CP_GREEN, COLOR_GREEN, -1);
        init_pair(CP_RED, COLOR_RED, -1);
        init_pair(CP_YELLOW, COLOR_YELLOW, -1);
        init_pair(CP_MAGENTA, COLOR_MAGENTA, -1);
        init_pair(CP_BLUE, COLOR_BLUE, -1);
        init_pair(CP_FOOTER, COLOR_BLACK, COLOR_WHITE);
        init_pair(CP_BTN_NO, COLOR_BLACK, COLOR_GREEN);
        init_pair(CP_BTN_YES, COLOR_WHITE, COLOR_RED);
    }
    s_term_raw_enabled = true;
}

void cleanup_tui(void) {
    if (s_term_raw_enabled) {
        if (!isendwin()) {
            endwin();
        }
        s_term_raw_enabled = false;
    }
}

void handle_signal(int sig) {
    (void)sig;
    if (g_config.enable_tui && s_term_raw_enabled) {
        if (!g_confirming_exit) {
            g_confirming_exit = true;
            g_exit_popup_focus = 0;
            return;
        }
    }
    g_server_running = 0;
    if (g_global_server_fd >= 0) {
        int fd = g_global_server_fd;
        g_global_server_fd = -1;
        close(fd);
    }
}

void print_log_line_ncurses(int y, int target_w, const char *line) {
    attron(COLOR_PAIR(CP_BLUE) | A_BOLD);
    mvprintw(y, 0, "│");
    attroff(COLOR_PAIR(CP_BLUE) | A_BOLD);
    printw(" ");

    int vis = 0;
    int i = 0;
    int current_attr = 0;

    while (line[i] != '\0' && vis < target_w) {
        if (line[i] == '\033' && line[i+1] == '[') {
            i += 2;
            int cp = 0;
            bool bold = false;
            bool dim = false;

            while (line[i] != '\0' && line[i] != 'm') {
                int num = 0;
                while (line[i] >= '0' && line[i] <= '9') {
                    num = num * 10 + (line[i] - '0');
                    i++;
                }
                if (num == 0) { cp = 0; bold = false; dim = false; }
                else if (num == 1) bold = true;
                else if (num == 2) dim = true;
                else if (num == 30) dim = true;
                else if (num == 31) cp = CP_RED;
                else if (num == 32) cp = CP_GREEN;
                else if (num == 33) cp = CP_YELLOW;
                else if (num == 34) cp = CP_BLUE;
                else if (num == 35) cp = CP_MAGENTA;
                else if (num == 36) cp = CP_CYAN;

                if (line[i] == ';') i++;
            }
            if (line[i] == 'm') i++;

            if (current_attr) {
                attroff(current_attr);
                current_attr = 0;
            }

            if (cp > 0) current_attr |= COLOR_PAIR(cp);
            if (bold) current_attr |= A_BOLD;
            if (dim) current_attr |= A_DIM;

            if (current_attr) attron(current_attr);
        } else {
            int seg_start = i;
            int seg_vis = 0;
            while (line[i] != '\0' && line[i] != '\033') {
                bool is_new_char = (((unsigned char)line[i] & 0xC0) != 0x80);
                if (is_new_char) {
                    if (vis + seg_vis >= target_w) break;
                    seg_vis++;
                }
                i++;
            }
            int seg_bytes = i - seg_start;
            if (seg_bytes > 0) {
                printw("%.*s", seg_bytes, &line[seg_start]);
                vis += seg_vis;
            }
            if (vis >= target_w) {
                while (line[i] != '\0' && line[i] != '\033') i++;
            }
        }
    }

    if (current_attr) {
        attroff(current_attr);
    }

    while (vis < target_w) {
        printw(" ");
        vis++;
    }

    attron(COLOR_PAIR(CP_BLUE) | A_BOLD);
    printw(" │");
    attroff(COLOR_PAIR(CP_BLUE) | A_BOLD);
}

void render_tui(void) {
    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    if (max_x < 80 || max_y < 18) {
        erase();
        attron(COLOR_PAIR(CP_RED) | A_BOLD);
        mvprintw(0, 0, "Terminal too small (%dx%d). Minimum 80x18 required.", max_x, max_y);
        attroff(COLOR_PAIR(CP_RED) | A_BOLD);
        refresh();
        return;
    }

    erase();

    // Calculate Uptime
    long elapsed = (long)(time(NULL) - g_start_time);
    int hours = (int)(elapsed / 3600);
    int mins = (int)((elapsed % 3600) / 60);
    int secs = (int)(elapsed % 60);

    // Global lock-free stats
    int total_active = 0;
    unsigned long total_reqs = 0;
    int num_b = g_num_backends;
    for (int i = 0; i < num_b; i++) {
        total_active += atomic_load_explicit(&g_backends[i].active_connections, memory_order_relaxed);
        total_reqs += atomic_load_explicit(&g_backends[i].total_requests_handled, memory_order_relaxed);
    }

    int row = 0;

    // --- 1. HEADER ---
    char hdr_left[128];
    snprintf(hdr_left, sizeof(hdr_left), "  ADVANCED LOAD BALANCER - DASHBOARD");
    char hdr_right[160];
    if (g_config.enable_cluster) {
        int tot_peers = 0;
        int alive_peers = cluster_get_alive_peers(&tot_peers);
        snprintf(hdr_right, sizeof(hdr_right),
                 "HA: %s %s│ Peers: %d/%d │ Synced: %d │ Uptime: %02d:%02d:%02d  ",
                 cluster_state_name(cluster_get_state()),
                 (g_config.virtual_ip[0] != '\0') ? g_config.virtual_ip : "",
                 alive_peers, tot_peers, session_table_count(),
                 hours, mins, secs);
    } else {
        snprintf(hdr_right, sizeof(hdr_right), "Uptime: %02d:%02d:%02d │ Status: RUNNING  ", hours, mins, secs);
    }

    attron(COLOR_PAIR(CP_HEADER) | A_BOLD);
    mvhline(row, 0, ' ', max_x);
    mvprintw(row, 0, "%s", hdr_left);
    int hr_vis = visible_len(hdr_right);
    if (max_x > hr_vis) {
        mvprintw(row, max_x - hr_vis, "%s", hdr_right);
    }
    attroff(COLOR_PAIR(CP_HEADER) | A_BOLD);
    row++;

    // Sub-header (line 1)
    mvhline(row, 0, ' ', max_x);
    move(row, 0);
    printw(" ");
    if (g_config.enable_udp_mode) {
        attron(COLOR_PAIR(CP_CYAN) | A_BOLD);
        printw("Port:");
        attroff(COLOR_PAIR(CP_CYAN) | A_BOLD);
        printw(" %d ", g_config.listen_port);

        attron(COLOR_PAIR(CP_YELLOW) | A_BOLD);
        printw("(UDP)");
        attroff(COLOR_PAIR(CP_YELLOW) | A_BOLD);
        printw(" │ ");

        attron(COLOR_PAIR(CP_CYAN) | A_BOLD);
        printw("Algo:");
        attroff(COLOR_PAIR(CP_CYAN) | A_BOLD);
        printw(" %s │ ", algorithm_name(g_config.current_algorithm));

        attron(COLOR_PAIR(CP_CYAN) | A_BOLD);
        printw("HC:");
        attroff(COLOR_PAIR(CP_CYAN) | A_BOLD);
        printw(" %s │ ", health_check_name(g_config.current_hc_type));

        attron(COLOR_PAIR(CP_CYAN) | A_BOLD);
        printw("Sessions:");
        attroff(COLOR_PAIR(CP_CYAN) | A_BOLD);
        printw(" %d │ ", total_active);

        attron(COLOR_PAIR(CP_CYAN) | A_BOLD);
        printw("Flows:");
        attroff(COLOR_PAIR(CP_CYAN) | A_BOLD);
        printw(" %lu", total_reqs);
    } else {
        attron(COLOR_PAIR(CP_CYAN) | A_BOLD);
        printw("Port:");
        attroff(COLOR_PAIR(CP_CYAN) | A_BOLD);
        printw(" %d ", g_config.listen_port);

        attron(COLOR_PAIR(CP_GREEN) | A_BOLD);
        printw("(TCP)");
        attroff(COLOR_PAIR(CP_GREEN) | A_BOLD);
        printw(" │ ");

        attron(COLOR_PAIR(CP_CYAN) | A_BOLD);
        printw("Algo:");
        attroff(COLOR_PAIR(CP_CYAN) | A_BOLD);
        printw(" %s │ ", algorithm_name(g_config.current_algorithm));

        attron(COLOR_PAIR(CP_CYAN) | A_BOLD);
        printw("HC:");
        attroff(COLOR_PAIR(CP_CYAN) | A_BOLD);
        printw(" %s │ ", health_check_name(g_config.current_hc_type));

        attron(COLOR_PAIR(CP_CYAN) | A_BOLD);
        printw("PPv1:");
        attroff(COLOR_PAIR(CP_CYAN) | A_BOLD);
        if (g_config.enable_proxy_protocol_v1) {
            attron(COLOR_PAIR(CP_GREEN) | A_BOLD);
            printw(" ON ");
            attroff(COLOR_PAIR(CP_GREEN) | A_BOLD);
        } else {
            attron(A_DIM);
            printw(" OFF ");
            attroff(A_DIM);
        }
        printw("│ ");

        attron(COLOR_PAIR(CP_CYAN) | A_BOLD);
        printw("SSL:");
        attroff(COLOR_PAIR(CP_CYAN) | A_BOLD);
        if (g_config.enable_ssl_offloading) {
            attron(COLOR_PAIR(CP_GREEN) | A_BOLD);
            printw(" ACTIVE ");
            attroff(COLOR_PAIR(CP_GREEN) | A_BOLD);
        } else {
            attron(A_DIM);
            printw(" OFF ");
            attroff(A_DIM);
        }
        printw("│ ");

        attron(COLOR_PAIR(CP_CYAN) | A_BOLD);
        printw("Conns:");
        attroff(COLOR_PAIR(CP_CYAN) | A_BOLD);
        printw(" %d │ ", total_active);

        attron(COLOR_PAIR(CP_CYAN) | A_BOLD);
        printw("Reqs:");
        attroff(COLOR_PAIR(CP_CYAN) | A_BOLD);
        printw(" %lu", total_reqs);
    }
    row++;

    // Separator line
    attron(COLOR_PAIR(CP_BLUE) | A_BOLD);
    move(row, 0);
    for (int col = 0; col < max_x; col++) {
        printw("─");
    }
    attroff(COLOR_PAIR(CP_BLUE) | A_BOLD);
    row++;

    // --- 2. SEZIONE REAL SERVICES ---
    attron(COLOR_PAIR(CP_YELLOW) | A_BOLD);
    mvprintw(row, 1, "REAL SERVICES (BACKEND FLEET STATUS)");
    attroff(COLOR_PAIR(CP_YELLOW) | A_BOLD);
    row++;

    int addr_w = max_x - 66;
    if (addr_w < 16) addr_w = 16;

    // Top table border
    attron(COLOR_PAIR(CP_BLUE) | A_BOLD);
    mvprintw(row, 0, "┌────┬");
    for (int k = 0; k < addr_w; k++) printw("─");
    printw("┬──────────┬────────────┬─────────┬────────────┬───────────┐");
    attroff(COLOR_PAIR(CP_BLUE) | A_BOLD);
    row++;

    // Table header
    attron(COLOR_PAIR(CP_BLUE) | A_BOLD);
    mvprintw(row, 0, "│");
    attroff(COLOR_PAIR(CP_BLUE) | A_BOLD);
    printw(" ID ");
    attron(COLOR_PAIR(CP_BLUE) | A_BOLD);
    printw("│");
    attroff(COLOR_PAIR(CP_BLUE) | A_BOLD);
    printw(" %-*.*s ", addr_w - 2, addr_w - 2, "ADDRESS");
    attron(COLOR_PAIR(CP_BLUE) | A_BOLD);
    printw("│");
    attroff(COLOR_PAIR(CP_BLUE) | A_BOLD);
    printw(" STATUS   ");
    attron(COLOR_PAIR(CP_BLUE) | A_BOLD);
    printw("│");
    attroff(COLOR_PAIR(CP_BLUE) | A_BOLD);
    printw(" LATENCY    ");
    attron(COLOR_PAIR(CP_BLUE) | A_BOLD);
    printw("│");
    attroff(COLOR_PAIR(CP_BLUE) | A_BOLD);
    printw(" CONNS   ");
    attron(COLOR_PAIR(CP_BLUE) | A_BOLD);
    printw("│");
    attroff(COLOR_PAIR(CP_BLUE) | A_BOLD);
    printw(" TOTAL REQS ");
    attron(COLOR_PAIR(CP_BLUE) | A_BOLD);
    printw("│");
    attroff(COLOR_PAIR(CP_BLUE) | A_BOLD);
    printw(" FAIL/OK   ");
    attron(COLOR_PAIR(CP_BLUE) | A_BOLD);
    printw("│");
    attroff(COLOR_PAIR(CP_BLUE) | A_BOLD);
    row++;

    // Middle table border
    attron(COLOR_PAIR(CP_BLUE) | A_BOLD);
    mvprintw(row, 0, "├────┼");
    for (int k = 0; k < addr_w; k++) printw("─");
    printw("┼──────────┼────────────┼─────────┼────────────┼───────────┤");
    attroff(COLOR_PAIR(CP_BLUE) | A_BOLD);
    row++;

    // Backend rows
    pthread_mutex_lock(&g_backend_mutex);
    for (int i = 0; i < g_num_backends; i++) {
        char addr_buf[128];
        if (g_backends[i].weight > 1) {
            snprintf(addr_buf, sizeof(addr_buf), "%s:%d [W:%d]", g_backends[i].ip, g_backends[i].port, g_backends[i].weight);
        } else {
            snprintf(addr_buf, sizeof(addr_buf), "%s:%d", g_backends[i].ip, g_backends[i].port);
        }

        char lat_buf[16];
        if (atomic_load_explicit(&g_backends[i].is_alive, memory_order_relaxed)) {
            snprintf(lat_buf, sizeof(lat_buf), "%6.2f ms", g_backends[i].latency_ms);
        } else {
            snprintf(lat_buf, sizeof(lat_buf), "    --   ");
        }

        char fo_buf[16];
        snprintf(fo_buf, sizeof(fo_buf), "%d/%d", g_backends[i].consecutive_failures, g_backends[i].consecutive_successes);

        int conns = atomic_load_explicit(&g_backends[i].active_connections, memory_order_relaxed);
        unsigned long reqs = atomic_load_explicit(&g_backends[i].total_requests_handled, memory_order_relaxed);

        attron(COLOR_PAIR(CP_BLUE) | A_BOLD);
        mvprintw(row, 0, "│");
        attroff(COLOR_PAIR(CP_BLUE) | A_BOLD);
        printw(" %-2d ", i);

        attron(COLOR_PAIR(CP_BLUE) | A_BOLD);
        printw("│");
        attroff(COLOR_PAIR(CP_BLUE) | A_BOLD);
        printw(" %-*.*s ", addr_w - 2, addr_w - 2, addr_buf);

        attron(COLOR_PAIR(CP_BLUE) | A_BOLD);
        printw("│ ");
        attroff(COLOR_PAIR(CP_BLUE) | A_BOLD);

        if (atomic_load_explicit(&g_backends[i].is_alive, memory_order_relaxed)) {
            attron(COLOR_PAIR(CP_GREEN) | A_BOLD);
            printw("● UP     ");
            attroff(COLOR_PAIR(CP_GREEN) | A_BOLD);
        } else {
            attron(COLOR_PAIR(CP_RED) | A_BOLD);
            printw("○ DOWN   ");
            attroff(COLOR_PAIR(CP_RED) | A_BOLD);
        }

        attron(COLOR_PAIR(CP_BLUE) | A_BOLD);
        printw("│");
        attroff(COLOR_PAIR(CP_BLUE) | A_BOLD);
        printw(" %-10s ", lat_buf);

        attron(COLOR_PAIR(CP_BLUE) | A_BOLD);
        printw("│");
        attroff(COLOR_PAIR(CP_BLUE) | A_BOLD);
        printw(" %-7d ", conns);

        attron(COLOR_PAIR(CP_BLUE) | A_BOLD);
        printw("│");
        attroff(COLOR_PAIR(CP_BLUE) | A_BOLD);
        printw(" %-10lu ", reqs);

        attron(COLOR_PAIR(CP_BLUE) | A_BOLD);
        printw("│");
        attroff(COLOR_PAIR(CP_BLUE) | A_BOLD);
        printw(" %-9s ", fo_buf);

        attron(COLOR_PAIR(CP_BLUE) | A_BOLD);
        printw("│");
        attroff(COLOR_PAIR(CP_BLUE) | A_BOLD);

        row++;
    }
    pthread_mutex_unlock(&g_backend_mutex);

    // Bottom table border
    attron(COLOR_PAIR(CP_BLUE) | A_BOLD);
    mvprintw(row, 0, "└────┴");
    for (int k = 0; k < addr_w; k++) printw("─");
    printw("┴──────────┴────────────┴─────────┴────────────┴───────────┘");
    attroff(COLOR_PAIR(CP_BLUE) | A_BOLD);
    row++;

    // --- 3. SEZIONE LIVE CONNECTION LOGS ---
    attron(COLOR_PAIR(CP_YELLOW) | A_BOLD);
    mvprintw(row, 1, "LIVE CONNECTION LOGS & EVENTS STREAM");
    attroff(COLOR_PAIR(CP_YELLOW) | A_BOLD);
    row++;

    int inner_w = max_x - 4;
    if (inner_w < 40) inner_w = 40;

    const char *log_title = "── LIVE CONNECTION LOGS ";
    int lt_vis = visible_len(log_title);
    attron(COLOR_PAIR(CP_BLUE) | A_BOLD);
    mvprintw(row, 0, "┌%s", log_title);
    int top_dashes = max_x - 2 - lt_vis;
    if (top_dashes < 2) top_dashes = 2;
    for (int k = 0; k < top_dashes; k++) printw("─");
    printw("┐");
    attroff(COLOR_PAIR(CP_BLUE) | A_BOLD);
    row++;

    int fixed_lines = 12 + num_b;
    int log_window = max_y - fixed_lines;
    if (log_window < 2) log_window = 2;

    char snapshot[MAX_LOG_LINES][LOG_LINE_LEN];
    int log_total = 0, log_head = 0;
    log_get_snapshot(snapshot, &log_total, &log_head);

    int start_idx = (log_total >= log_window) ? (log_head - log_window + MAX_LOG_LINES) % MAX_LOG_LINES : 0;
    int items_to_print = (log_total >= log_window) ? log_window : log_total;

    for (int k = 0; k < log_window && row < max_y - 2; k++) {
        if (k < items_to_print) {
            int cur = (start_idx + k) % MAX_LOG_LINES;
            print_log_line_ncurses(row, inner_w, snapshot[cur]);
        } else {
            print_log_line_ncurses(row, inner_w, "");
        }
        row++;
    }

    // Bottom log box border
    attron(COLOR_PAIR(CP_BLUE) | A_BOLD);
    mvprintw(row, 0, "└");
    for (int k = 0; k < max_x - 2; k++) printw("─");
    printw("┘");
    attroff(COLOR_PAIR(CP_BLUE) | A_BOLD);

    // --- 4. COMMAND FOOTER ---
    char foot_text[160];
    if (g_confirming_exit) {
        snprintf(foot_text, sizeof(foot_text), " [◄ / ► / Tab] Select   │   [Enter / Space] Confirm Choice   │   [ESC] Cancel");
    } else if (g_config.enable_cluster) {
        snprintf(foot_text, sizeof(foot_text), " [Q] Exit │ [R] Reset │ [A] Algo │ [H] Health │ [P] PPv1 │ [C] VRRP Failover");
    } else {
        snprintf(foot_text, sizeof(foot_text), " [Q / Ctrl+C] Exit  │  [R] Reset  │  [A] Algorithm  │  [H] Health Check  │  [P] PROXY v1");
    }

    attron(COLOR_PAIR(CP_FOOTER) | A_BOLD);
    mvhline(max_y - 1, 0, ' ', max_x);
    mvprintw(max_y - 1, 0, "%s", foot_text);
    attroff(COLOR_PAIR(CP_FOOTER) | A_BOLD);

    // --- 5. MODAL EXIT CONFIRMATION POPUP ---
    if (g_confirming_exit) {
        int box_w = 56;
        int box_h = 7;
        if (box_w > max_x - 4) box_w = max_x - 4;
        int start_y = (max_y - box_h) / 2;
        int start_x = (max_x - box_w) / 2;

        for (int y = 0; y < box_h; y++) {
            mvhline(start_y + y, start_x, ' ', box_w);
        }

        attron(COLOR_PAIR(CP_RED) | A_BOLD);
        mvprintw(start_y, start_x, "┌");
        const char *title = " [!] CONFIRM EXIT ";
        int t_len = visible_len(title);
        int d1 = (box_w - 2 - t_len) / 2;
        int d2 = box_w - 2 - t_len - d1;
        for (int k = 0; k < d1; k++) printw("─");
        attron(COLOR_PAIR(CP_YELLOW) | A_BOLD);
        printw("%s", title);
        attroff(COLOR_PAIR(CP_YELLOW) | A_BOLD);
        attron(COLOR_PAIR(CP_RED) | A_BOLD);
        for (int k = 0; k < d2; k++) printw("─");
        printw("┐");

        for (int y = 1; y < box_h - 1; y++) {
            mvprintw(start_y + y, start_x, "│");
            mvprintw(start_y + y, start_x + box_w - 1, "│");
        }

        mvprintw(start_y + box_h - 1, start_x, "└");
        for (int k = 0; k < box_w - 2; k++) printw("─");
        printw("┘");
        attroff(COLOR_PAIR(CP_RED) | A_BOLD);

        const char *msg = "Are you sure you want to shut down the Load Balancer?";
        int msg_len = visible_len(msg);
        mvprintw(start_y + 2, start_x + (box_w - msg_len) / 2, "%s", msg);

        int opt_len = 33;
        int opt_x = start_x + (box_w - opt_len) / 2;
        move(start_y + 4, opt_x);

        if (g_exit_popup_focus == 0) {
            attron(COLOR_PAIR(CP_BTN_NO) | A_BOLD);
            printw(" < No, Cancel > ");
            attroff(COLOR_PAIR(CP_BTN_NO) | A_BOLD);

            printw("    ");

            attron(COLOR_PAIR(CP_RED));
            printw("[ Yes, Exit ]");
            attroff(COLOR_PAIR(CP_RED));
        } else {
            attron(COLOR_PAIR(CP_GREEN));
            printw("[ No, Cancel ]");
            attroff(COLOR_PAIR(CP_GREEN));

            printw("    ");

            attron(COLOR_PAIR(CP_BTN_YES) | A_BOLD);
            printw(" < Yes, Exit > ");
            attroff(COLOR_PAIR(CP_BTN_YES) | A_BOLD);
        }
    }

    refresh();
}

void *tui_thread(void *arg) {
    (void)arg;
    while (g_server_running) {
        render_tui();

        int c;
        while ((c = getch()) != ERR) {
            if (g_confirming_exit) {
                if (c == KEY_LEFT || c == KEY_RIGHT || c == KEY_UP || c == KEY_DOWN || c == '\t') {
                    g_exit_popup_focus = 1 - g_exit_popup_focus;
                } else if (c == 'n' || c == 'N') {
                    g_exit_popup_focus = 0;
                } else if (c == 's' || c == 'S' || c == 'y' || c == 'Y') {
                    g_exit_popup_focus = 1;
                } else if (c == '\n' || c == '\r' || c == KEY_ENTER || c == ' ') {
                    if (g_exit_popup_focus == 1) {
                        g_server_running = 0;
                        if (g_global_server_fd >= 0) {
                            close(g_global_server_fd);
                            g_global_server_fd = -1;
                        }
                        g_confirming_exit = false;
                        break;
                    } else {
                        g_confirming_exit = false;
                    }
                } else if (c == 27 || c == 'c' || c == 'C') {
                    g_confirming_exit = false;
                }
            } else {
                if (c == 'q' || c == 'Q' || c == 3) {
                    g_confirming_exit = true;
                    g_exit_popup_focus = 0;
                } else if (c == 'r' || c == 'R') {
                    reset_backend_stats();
                } else if (c == 'a' || c == 'A') {
                    pthread_mutex_lock(&g_backend_mutex);
                    g_config.current_algorithm = (BalancerAlgorithm)((g_config.current_algorithm + 1) % 6);
                    pthread_mutex_unlock(&g_backend_mutex);
                    add_log("\033[1;36m[CONFIG]\033[0m Algorithm switched to: %s", algorithm_name(g_config.current_algorithm));
                } else if (c == 'h' || c == 'H') {
                    pthread_mutex_lock(&g_backend_mutex);
                    g_config.current_hc_type = (HealthCheckType)((g_config.current_hc_type + 1) % 3);
                    pthread_mutex_unlock(&g_backend_mutex);
                    add_log("\033[1;35m[HEALTH]\033[0m Health Check switched to: %s", health_check_name(g_config.current_hc_type));
                    perform_health_check_cycle(false);
                } else if (c == 'p' || c == 'P') {
                    g_config.enable_proxy_protocol_v1 = !g_config.enable_proxy_protocol_v1;
                    add_log("\033[1;35m[CONFIG]\033[0m PROXY Protocol v1 to backends: %s",
                            g_config.enable_proxy_protocol_v1 ? "\033[1;32mENABLED\033[0m" : "\033[1;31mDISABLED\033[0m");
                } else if ((c == 'c' || c == 'C') && g_config.enable_cluster) {
                    cluster_trigger_stepdown();
                } else if (c == KEY_RESIZE) {
                    // Terminal resize handled in next frame
                }
            }
        }

        usleep(100000); // 10 FPS (100ms)
    }
    return NULL;
}

