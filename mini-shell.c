/*
 * ================================================================
 *  Project: Mini Shell
 *  File: mini-shell.c
 *  Description:
 *      A lightweight UNIX-like shell implemented in C that supports:
 *        • Command execution with arguments
 *        • I/O redirection (<, >, >>, 2>, &>, etc.)
 *        • Background jobs (&) with job control (jobs, fg, bg)
 *        • Command history with arrow key navigation
 *        • Pipelines using the | operator
 *        • Signal handling (SIGINT, SIGCHLD)
 *        • Persistent history storage (~/.mini_shell_history)
 *
 *  Compilation:
 *      make mini-shell
 *
 *  Usage:
 *      ./mini-shell
 *
 *  License:
 *      MIT License
 * ================================================================
 */

#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

/* ---------- Forward declarations / prototypes ---------- */
char **parse_line(char *line);
static int shell_cd(char **argv);
static int shell_help(char **argv);
static int shell_exit(char **argv);
static int builtin_jobs(char **argv);
static int shell_fg(char **argv);
static int shell_bg(char **argv);
static int builtin_history(char **argv);

/* ---------- Configuration ---------- */
#define TOKEN_BUF_SIZE 64
#define HISTORY_FILE ".mini_shell_history"
#define HISTORY_MAX 1000
#define JOBS_MAX 256

/* ---------- Utility: safe strdup ---------- */
static char *safe_strdup_or_null(const char *s)
{
    if (!s)
        return NULL;
    char *t = strdup(s);
    return t; /* caller handles NULL */
}

/* ---------- History ---------- */
static char *history[HISTORY_MAX];
static int history_count = 0;

static char history_path[PATH_MAX];

static void history_add(const char *line)
{
    if (!line || line[0] == '\0')
        return;
    if (history_count >= HISTORY_MAX)
    {
        free(history[0]);
        memmove(&history[0], &history[1], sizeof(char *) * (HISTORY_MAX - 1));
        history_count--;
    }
    history[history_count++] = safe_strdup_or_null(line);
}

/* load history from ~/.mini_shell_history */
static void history_load(void)
{
    const char *home = getenv("HOME");
    if (!home)
    {
        struct passwd *pw = getpwuid(getuid());
        if (pw)
            home = pw->pw_dir;
    }
    if (!home)
        return;
    snprintf(history_path, sizeof(history_path), "%s/%s", home, HISTORY_FILE);
    FILE *f = fopen(history_path, "r");
    if (!f)
        return;
    char *line = NULL;
    size_t n = 0;
    ssize_t r;
    while ((r = getline(&line, &n, f)) > 0)
    {
        if (r > 0 && line[r - 1] == '\n')
            line[r - 1] = '\0';
        history_add(line);
    }
    free(line);
    fclose(f);
}

/* save history to file (append new entries) */
static void history_save(void)
{
    if (!history_path[0])
        return;
    FILE *f = fopen(history_path, "w");
    if (!f)
        return;
    for (int i = 0; i < history_count; ++i)
    {
        fprintf(f, "%s\n", history[i]);
    }
    fclose(f);
}

/* print history */
static int builtin_history(char **argv)
{
    (void) argv;
    for (int i = 0; i < history_count; ++i)
    {
        printf("%4d  %s\n", i + 1, history[i]);
    }
    return 1;
}

/* ---------- Jobs (background job management) ---------- */
typedef enum { JOB_RUNNING = 0, JOB_DONE = 1, JOB_STOPPED = 2 } job_state_t;

typedef struct job
{
    int id;        /* job id starting from 1 */
    pid_t pgid;    /* process group id or leader pid */
    pid_t leader;  /* leader pid */
    char *cmdline; /* strdup'd command line */
    job_state_t state;
} job_t;

static job_t *jobs[JOBS_MAX];
static int job_count = 0;
static int next_job_id = 1;

/* notification queue populated by SIGCHLD handler (signal-safe minimal storage) */
#define NOTIFY_MAX 256
static pid_t notify_pids[NOTIFY_MAX];
static int notify_states[NOTIFY_MAX]; /* 0 -> exited, 1 -> stopped, 2 -> continued */
static int notify_head = 0;
static int notify_tail = 0;

static void notify_push(pid_t pid, int st)
{
    int next = (notify_tail + 1) % NOTIFY_MAX;
    if (next == notify_head)
        return; /* queue full: drop */
    notify_pids[notify_tail] = pid;
    notify_states[notify_tail] = st;
    notify_tail = next;
}
static int notify_pop(pid_t *p, int *s)
{
    if (notify_head == notify_tail)
        return 0;
    *p = notify_pids[notify_head];
    *s = notify_states[notify_head];
    notify_head = (notify_head + 1) % NOTIFY_MAX;
    return 1;
}

/* find job by pgid or leader pid or job id */
static job_t *job_find_by_pgid(pid_t pgid)
{
    for (int i = 0; i < job_count; i++)
    {
        if (jobs[i] && jobs[i]->pgid == pgid)
            return jobs[i];
    }
    return NULL;
}
static job_t *job_find_by_pid(pid_t pid)
{
    for (int i = 0; i < job_count; i++)
    {
        if (jobs[i] && jobs[i]->leader == pid)
            return jobs[i];
    }
    return NULL;
}
static job_t *job_find_by_id(int id)
{
    for (int i = 0; i < job_count; i++)
    {
        if (jobs[i] && jobs[i]->id == id)
            return jobs[i];
    }
    return NULL;
}

/* add a job */
static job_t *job_add(pid_t leader, pid_t pgid, const char *cmdline, job_state_t state)
{
    if (job_count >= JOBS_MAX)
        return NULL;
    job_t *j = calloc(1, sizeof(job_t));
    if (!j)
        return NULL;
    j->id = next_job_id++;
    j->leader = leader;
    j->pgid = pgid;
    j->cmdline = safe_strdup_or_null(cmdline ? cmdline : "");
    j->state = state;
    jobs[job_count++] = j;
    return j;
}

/* remove job (free) */
static void job_remove(job_t *j)
{
    if (!j)
        return;
    /* remove from array */
    int idx = -1;
    for (int i = 0; i < job_count; i++)
        if (jobs[i] == j)
        {
            idx = i;
            break;
        }
    if (idx >= 0)
    {
        free(j->cmdline);
        free(j);
        for (int k = idx; k + 1 < job_count; k++)
            jobs[k] = jobs[k + 1];
        jobs[job_count - 1] = NULL;
        job_count--;
    }
}

/* update job state */
static void job_set_state(job_t *j, job_state_t s)
{
    if (!j)
        return;
    j->state = s;
}

/* print jobs */
static int builtin_jobs(char **argv)
{
    (void) argv;
    for (int i = 0; i < job_count; i++)
    {
        job_t *j = jobs[i];
        if (!j)
            continue;
        const char *st = (j->state == JOB_RUNNING)   ? "Running"
                         : (j->state == JOB_STOPPED) ? "Stopped"
                                                     : "Done";
        printf("[%d] %s  pid=%d  %s\n", j->id, st, (int) j->leader, j->cmdline);
    }
    return 1;
}

/* ---------- Signal handling ---------- */

/* SIGCHLD handler: reap children and push notifications (async-signal-safe minimal ops) */
static void sigchld_handler(int signo)
{
    (void) signo;
    int saved_errno = errno;
    while (1)
    {
        int status;
        pid_t pid = waitpid(-1, &status, WNOHANG | WUNTRACED | WCONTINUED);
        if (pid <= 0)
            break;
        if (WIFEXITED(status) || WIFSIGNALED(status))
        {
            notify_push(pid, 0); /* exited */
        }
        else if (WIFSTOPPED(status))
        {
            notify_push(pid, 1); /* stopped */
        }
        else if (WIFCONTINUED(status))
        {
            notify_push(pid, 2); /* continued */
        }
    }
    errno = saved_errno;
}

/* designate shell behaviour: ignore SIGINT, set SIGCHLD handler */
static int init_signal_handlers(void)
{
    struct sigaction sa;
    if (signal(SIGINT, SIG_IGN) == SIG_ERR)
    {
        perror("signal SIGINT");
        return -1;
    }
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGCHLD, &sa, NULL) == -1)
    {
        perror("sigaction SIGCHLD");
        return -1;
    }
    return 0;
}

/* process notifications in main loop: map pid -> job, update state, print messages */
static void process_notifications(void)
{
    pid_t p;
    int st;
    while (notify_pop(&p, &st))
    {
        job_t *j = job_find_by_pid(p);
        if (!j)
            j = job_find_by_pgid(p);
        if (!j)
        {
            /* maybe an orphan/child we didn't track; ignore */
            continue;
        }
        if (st == 0)
        {
            /* exited */
            job_set_state(j, JOB_DONE);
            printf("\n[notify] job %d (pid %d) done: %s\n", j->id, (int) j->leader, j->cmdline);
            /* we keep done jobs in list so user can inspect; optionally remove immediately */
        }
        else if (st == 1)
        {
            job_set_state(j, JOB_STOPPED);
            printf("\n[notify] job %d (pid %d) stopped: %s\n", j->id, (int) j->leader, j->cmdline);
        }
        else if (st == 2)
        {
            job_set_state(j, JOB_RUNNING);
            printf("\n[notify] job %d (pid %d) continued: %s\n", j->id, (int) j->leader,
                   j->cmdline);
        }
    }
}

/* ---------- Line editing / history-aware read_line using termios ---------- */

/* Save original terminal attributes so we can restore them. */
static struct termios orig_termios;
static int raw_mode_enabled = 0;

static void disable_raw_mode(void)
{
    if (!raw_mode_enabled)
        return;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
    raw_mode_enabled = 0;
}

/* Enable a simple raw mode (non-canonical, no echo). */
static int enable_raw_mode(void)
{
    if (raw_mode_enabled)
        return 0;
    if (tcgetattr(STDIN_FILENO, &orig_termios) == -1)
        return -1;
    struct termios raw = orig_termios;
    /* Cast mask operands to tcflag_t to avoid signedness warnings on strict compilers */
    raw.c_lflag &= ~((tcflag_t) (ECHO | ICANON | IEXTEN | ISIG));
    raw.c_iflag &= ~((tcflag_t) (IXON | ICRNL | BRKINT | INPCK | ISTRIP));
    raw.c_oflag &= ~((tcflag_t) (OPOST));
    raw.c_cflag |= (tcflag_t) (CS8);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == -1)
        return -1;
    raw_mode_enabled = 1;
    return 0;
}

/* Helper: write n bytes to stdout, loop until all written */
static ssize_t xwrite(const void *buf, size_t n)
{
    const char *p = buf;
    size_t left = n;
    while (left > 0)
    {
        ssize_t w = write(STDOUT_FILENO, p, left);
        if (w <= 0)
            return -1;
        left -= (size_t) w;
        p += w;
    }
    return (ssize_t) n;
}

/* Utility to refresh the displayed line given buffer and cursor pos.
   Simple approach: emit "\r", then the prompt, then buffer, then clear to end,
   and then move cursor to position. */
static void refresh_line(const char *prompt, char *buf, size_t len, size_t pos)
{
    xwrite("\r", 1);
    xwrite(prompt, strlen(prompt));
    xwrite(buf, len);
    /* clear to end of line */
    xwrite("\x1b[K", 3);
    /* move cursor to desired column (prompt_len + pos) */
    size_t prompt_len = strlen(prompt);
    size_t desired = prompt_len + pos;
    char seq[64];
    /* move to column 'desired' by moving right desired times from start */
    snprintf(seq, sizeof(seq), "\r\x1b[%zuC", desired);
    xwrite(seq, strlen(seq));
}

/* Copy history entry into buffer (clears current buffer). */
static void replace_buffer_from_history(char *buf, size_t *lenp, size_t *posp, int hindex)
{
    if (hindex < 0 || hindex >= history_count)
    {
        (*lenp) = 0;
        (*posp) = 0;
        buf[0] = '\0';
        return;
    }
    const char *h = history[hindex];
    size_t n = strlen(h);
    memcpy(buf, h, n);
    buf[n] = '\0';
    *lenp = n;
    *posp = n;
}

/* read_line: improved line editor supporting arrow keys & history navigation.
   Returns malloc'd string (caller must free) or NULL on EOF/error. */
char *read_line(void)
{
    const char *prompt = "mini-shell> "; /* caller prints it already; keep for refresh */

    if (enable_raw_mode() == -1)
    {
        /* fallback to simple read if cannot enable raw mode */
        size_t buff_size = 128;
        char *buffer = malloc(buff_size);
        if (!buffer)
            return NULL;
        size_t pos = 0;
        char c;
        /* print prompt */
        printf("%s", prompt);
        fflush(stdout);
        while (1)
        {
            ssize_t n = read(STDIN_FILENO, &c, 1);
            if (n == 0)
            {
                free(buffer);
                return NULL;
            }
            if (n < 0)
            {
                free(buffer);
                return NULL;
            }
            if (c == '\n')
            {
                buffer[pos] = '\0';
                disable_raw_mode();
                return buffer;
            }
            buffer[pos++] = c;
            if (pos + 1 >= buff_size)
            {
                buff_size *= 2;
                char *tmp = realloc(buffer, buff_size);
                if (!tmp)
                {
                    free(buffer);
                    disable_raw_mode();
                    return NULL;
                }
                buffer = tmp;
            }
        }
    }

    /* allocate an editable buffer */
    size_t buf_cap = 1024;
    char *buf = malloc(buf_cap);
    if (!buf)
    {
        disable_raw_mode();
        return NULL;
    }
    size_t len = 0, pos = 0;
    buf[0] = '\0';

    /* history navigation index:
       -1 means not currently browsing history
       when user presses Up, set to history_count-1 and go backwards */
    int hidx = -1;

    /* We print the prompt and refresh line */
    xwrite(prompt, strlen(prompt));
    refresh_line(prompt, buf, len, pos);

    while (1)
    {
        char c;
        ssize_t r = read(STDIN_FILENO, &c, 1);
        if (r <= 0)
        {
            /* EOF or error */
            free(buf);
            disable_raw_mode();
            return NULL;
        }

        if (c == '\r' || c == '\n')
        {
            /* newline -> finish line */
            buf[len] = '\0';
            disable_raw_mode();
            xwrite("\n", 1);
            char *res = safe_strdup_or_null(buf);
            free(buf);
            return res;
        }
        else if (c == 127 || c == 8)
        {
            /* Backspace */
            if (pos > 0)
            {
                memmove(buf + pos - 1, buf + pos, len - pos);
                pos--;
                len--;
                buf[len] = '\0';
                refresh_line(prompt, buf, len, pos);
            }
        }
        else if (c == '\x04')
        {
            /* Ctrl+D: if line empty -> EOF (return NULL), else delete at cursor */
            if (len == 0)
            {
                free(buf);
                disable_raw_mode();
                return NULL;
            }
            else
            {
                if (pos < len)
                {
                    memmove(buf + pos, buf + pos + 1, len - pos - 1);
                    len--;
                    buf[len] = '\0';
                    refresh_line(prompt, buf, len, pos);
                }
            }
        }
        else if (c == '\x03')
        {
            /* Ctrl+C: return empty line (print ^C) */
            buf[0] = '\0';
            len = pos = 0;
            xwrite("^C\n", 3);
            disable_raw_mode();
            char *res = safe_strdup_or_null("");
            free(buf);
            return res;
        }
        else if (c == '\x1b')
        {
            /* Escape sequence (likely arrow keys) */
            char seq[3];
            if (read(STDIN_FILENO, &seq[0], 1) <= 0)
                continue;
            if (read(STDIN_FILENO, &seq[1], 1) <= 0)
                continue;
            if (seq[0] == '[')
            {
                if (seq[1] >= '0' && seq[1] <= '9')
                {
                    /* extended sequence, read one more */
                    char seq2;
                    if (read(STDIN_FILENO, &seq2, 1) <= 0)
                        continue;
                    (void) seq2; /* ignore extended for now */
                }
                else
                {
                    if (seq[1] == 'A')
                    {
                        /* Up arrow -> previous history */
                        if (history_count == 0)
                        { /* nothing */
                        }
                        else
                        {
                            if (hidx == -1)
                                hidx = history_count - 1;
                            else if (hidx > 0)
                                hidx--;
                            replace_buffer_from_history(buf, &len, &pos, hidx);
                            refresh_line(prompt, buf, len, pos);
                        }
                    }
                    else if (seq[1] == 'B')
                    {
                        /* Down arrow -> next history */
                        if (history_count == 0)
                        { /* nothing */
                        }
                        else
                        {
                            if (hidx == -1)
                            {
                                /* nothing */
                            }
                            else if (hidx < history_count - 1)
                            {
                                hidx++;
                                replace_buffer_from_history(buf, &len, &pos, hidx);
                                refresh_line(prompt, buf, len, pos);
                            }
                            else
                            {
                                /* move past last => empty buffer */
                                hidx = -1;
                                len = pos = 0;
                                buf[0] = '\0';
                                refresh_line(prompt, buf, len, pos);
                            }
                        }
                    }
                    else if (seq[1] == 'C')
                    {
                        /* Right arrow */
                        if (pos < len)
                        {
                            pos++;
                            refresh_line(prompt, buf, len, pos);
                        }
                    }
                    else if (seq[1] == 'D')
                    {
                        /* Left arrow */
                        if (pos > 0)
                        {
                            pos--;
                            refresh_line(prompt, buf, len, pos);
                        }
                    }
                }
            }
        }
        else if ((unsigned char) c >= 0x20 && (unsigned char) c <= 0x7e)
        {
            /* printable character: insert at cursor */
            if (len + 2 >= buf_cap)
            {
                size_t newcap = buf_cap * 2;
                char *tmp = realloc(buf, newcap);
                if (!tmp)
                {
                    free(buf);
                    disable_raw_mode();
                    return NULL;
                }
                buf = tmp;
                buf_cap = newcap;
            }
            if (pos < len)
                memmove(buf + pos + 1, buf + pos, len - pos);
            buf[pos] = c;
            pos++;
            len++;
            buf[len] = '\0';
            refresh_line(prompt, buf, len, pos);
            /* when user types, they are no longer browsing history */
            hidx = -1;
        }
        else
        {
            /* ignore other control codes */
        }
    }
    /* unreachable */
    disable_raw_mode();
    free(buf);
    return NULL;
}

/* ---------- Redirection stripping  ---------- */
/* Returns newly allocated argv suitable for exec; sets infile/outfile/errfile etc. */
static void free_str_array_entries(char **arr, int n)
{
    if (!arr)
        return;
    for (int i = 0; i < n; i++)
        if (arr[i])
            free(arr[i]);
}

static char **strip_redirection_and_get_files(char **argv, char **infile, char **outfile,
                                              char **errfile, int *append_out, int *err_to_fd,
                                              int *out_to_fd, int *in_from_fd, int *out_and_err)
{
    int count = 0;
    for (int i = 0; argv[i] != NULL; i++)
        count++;
    char **newargv = malloc((size_t) (count + 1) * sizeof(char *));
    if (!newargv)
        return NULL;
    *infile = NULL;
    *outfile = NULL;
    *errfile = NULL;
    *append_out = 0;
    *err_to_fd = -1;
    *out_to_fd = -1;
    *in_from_fd = -1;
    *out_and_err = 0;
    int j = 0;
    for (int i = 0; i < count; i++)
    {
        if (strcmp(argv[i], "<") == 0)
        {
            if (i + 1 >= count || argv[i + 1] == NULL)
            {
                fprintf(stderr, "Syntax error: expected filename or &N after '<'\n");
                free_str_array_entries(newargv, j);
                free(newargv);
                return NULL;
            }
            if (argv[i + 1][0] == '&' && isdigit((unsigned char) argv[i + 1][1]))
            {
                int target = atoi(argv[i + 1] + 1);
                *in_from_fd = target;
                i++;
                continue;
            }
            *infile = safe_strdup_or_null(argv[i + 1]);
            if (!*infile)
            {
                free_str_array_entries(newargv, j);
                free(newargv);
                return NULL;
            }
            i++;
            continue;
        }
        if (strcmp(argv[i], "&>") == 0 || strcmp(argv[i], "&>>") == 0)
        {
            int is_append = (strcmp(argv[i], "&>>") == 0);
            if (i + 1 >= count || argv[i + 1] == NULL)
            {
                fprintf(stderr, "Syntax error: expected filename after '%s'\n", argv[i]);
                free_str_array_entries(newargv, j);
                free(newargv);
                return NULL;
            }
            *outfile = safe_strdup_or_null(argv[i + 1]);
            if (!*outfile)
            {
                free_str_array_entries(newargv, j);
                free(newargv);
                return NULL;
            }
            *append_out = is_append;
            *out_and_err = 1;
            i++;
            continue;
        }
        if (strcmp(argv[i], ">") == 0 || strcmp(argv[i], ">>") == 0)
        {
            int is_append = (strcmp(argv[i], ">>") == 0);
            if (i + 1 >= count || argv[i + 1] == NULL)
            {
                fprintf(stderr, "Syntax error: expected filename or &N after '%s'\n", argv[i]);
                free_str_array_entries(newargv, j);
                free(newargv);
                return NULL;
            }
            if (argv[i + 1][0] == '&' && isdigit((unsigned char) argv[i + 1][1]))
            {
                int target = atoi(argv[i + 1] + 1);
                *out_to_fd = target;
                *append_out = is_append;
                i++;
                continue;
            }
            *outfile = safe_strdup_or_null(argv[i + 1]);
            if (!*outfile)
            {
                free_str_array_entries(newargv, j);
                free(newargv);
                return NULL;
            }
            *append_out = is_append;
            i++;
            continue;
        }
        if (isdigit((unsigned char) argv[i][0]))
        {
            size_t slen = strlen(argv[i]);
            size_t p = 0;
            while (p < slen && isdigit((unsigned char) argv[i][p]))
                p++;
            if (p < slen && argv[i][p] == '>' && argv[i][p + 1] == '\0')
            {
                int fd_from = atoi(argv[i]);
                if (i + 1 >= count || argv[i + 1] == NULL)
                {
                    fprintf(stderr, "Syntax error: expected target after '%s'\n", argv[i]);
                    free_str_array_entries(newargv, j);
                    free(newargv);
                    return NULL;
                }
                if (argv[i + 1][0] == '&' && isdigit((unsigned char) argv[i + 1][1]))
                {
                    int target_fd = atoi(argv[i + 1] + 1);
                    if (fd_from == 2)
                    {
                        *err_to_fd = target_fd;
                        i++;
                        continue;
                    }
                    else if (fd_from == 1)
                    {
                        *out_to_fd = target_fd;
                        i++;
                        continue;
                    }
                    else if (fd_from == 0)
                    {
                        *in_from_fd = target_fd;
                        i++;
                        continue;
                    }
                    else
                    {
                        fprintf(stderr, "Unsupported numeric fd duplication for fd %d\n", fd_from);
                        free_str_array_entries(newargv, j);
                        free(newargv);
                        return NULL;
                    }
                }
                if (fd_from == 2)
                {
                    *errfile = safe_strdup_or_null(argv[i + 1]);
                    if (!*errfile)
                    {
                        free_str_array_entries(newargv, j);
                        free(newargv);
                        return NULL;
                    }
                    i++;
                    continue;
                }
                else if (fd_from == 1)
                {
                    *outfile = safe_strdup_or_null(argv[i + 1]);
                    if (!*outfile)
                    {
                        free_str_array_entries(newargv, j);
                        free(newargv);
                        return NULL;
                    }
                    i++;
                    continue;
                }
                else if (fd_from == 0)
                {
                    *infile = safe_strdup_or_null(argv[i + 1]);
                    if (!*infile)
                    {
                        free_str_array_entries(newargv, j);
                        free(newargv);
                        return NULL;
                    }
                    i++;
                    continue;
                }
                else
                {
                    fprintf(stderr, "Unsupported numeric fd redirection: %s\n", argv[i]);
                    free_str_array_entries(newargv, j);
                    free(newargv);
                    return NULL;
                }
            }
        }
        if (argv[i][0] == '&' && isdigit((unsigned char) argv[i][1]))
        {
            fprintf(stderr, "Syntax error: unexpected token '%s'\n", argv[i]);
            free_str_array_entries(newargv, j);
            free(newargv);
            return NULL;
        }
        newargv[j] = safe_strdup_or_null(argv[i]);
        if (!newargv[j])
        {
            free_str_array_entries(newargv, j);
            free(newargv);
            return NULL;
        }
        j++;
    }
    newargv[j] = NULL;
    return newargv;
}

/* ---------- Launch single command (with redirections), background support ---------- */
static int launch_command_and_redirect(char **argv, int background, const char *orig_cmdline)
{
    pid_t child;
    int status;
    char *infile = NULL, *outfile = NULL, *errfile = NULL;
    int append_flag = 0, err_to_fd = -1, out_to_fd = -1, in_from_fd = -1, out_and_err = 0;
    char **exec_argv =
        strip_redirection_and_get_files(argv, &infile, &outfile, &errfile, &append_flag, &err_to_fd,
                                        &out_to_fd, &in_from_fd, &out_and_err);
    if (!exec_argv)
    {
        if (infile)
            free(infile);
        if (outfile)
            free(outfile);
        if (errfile)
            free(errfile);
        return 1;
    }
    if (exec_argv[0] == NULL)
    {
        fprintf(stderr, "Error: no command specified (only redirection tokens)\n");
        for (size_t i = 0; exec_argv[i] != NULL; i++)
            free(exec_argv[i]);
        free(exec_argv);
        if (infile)
            free(infile);
        if (outfile)
            free(outfile);
        if (errfile)
            free(errfile);
        return 1;
    }

    child = fork();
    if (child == -1)
    {
        perror("fork");
        for (size_t i = 0; exec_argv[i] != NULL; i++)
            free(exec_argv[i]);
        free(exec_argv);
        if (infile)
            free(infile);
        if (outfile)
            free(outfile);
        if (errfile)
            free(errfile);
        return 1;
    }
    else if (child == 0)
    {
        /* Child: restore default SIGINT, run command */
        signal(SIGINT, SIG_DFL);

        if (in_from_fd >= 0)
        {
            if (dup2(in_from_fd, STDIN_FILENO) == -1)
            {
                perror("dup2 stdin from fd");
                _exit(EXIT_FAILURE);
            }
        }
        if (infile)
        {
            int fd = open(infile, O_RDONLY);
            if (fd < 0)
            {
                perror("open infile");
                _exit(EXIT_FAILURE);
            }
            if (dup2(fd, STDIN_FILENO) == -1)
            {
                perror("dup2 infile");
                close(fd);
                _exit(EXIT_FAILURE);
            }
            close(fd);
        }

        if (outfile && out_and_err)
        {
            int flags = O_WRONLY | O_CREAT;
            if (append_flag)
                flags |= O_APPEND;
            else
                flags |= O_TRUNC;
            int fd = open(outfile, flags, 0644);
            if (fd < 0)
            {
                perror("open outfile for &>");
                _exit(EXIT_FAILURE);
            }
            if (dup2(fd, STDOUT_FILENO) == -1)
            {
                perror("dup2 outfile");
                close(fd);
                _exit(EXIT_FAILURE);
            }
            if (dup2(fd, STDERR_FILENO) == -1)
            {
                perror("dup2 outfile->stderr");
                close(fd);
                _exit(EXIT_FAILURE);
            }
            close(fd);
        }
        else
        {
            if (out_to_fd >= 0)
            {
                if (dup2(out_to_fd, STDOUT_FILENO) == -1)
                {
                    perror("dup2 stdout->fd");
                    _exit(EXIT_FAILURE);
                }
            }
            if (outfile)
            {
                int flags = O_WRONLY | O_CREAT;
                if (append_flag)
                    flags |= O_APPEND;
                else
                    flags |= O_TRUNC;
                int fd = open(outfile, flags, 0644);
                if (fd < 0)
                {
                    perror("open outfile");
                    _exit(EXIT_FAILURE);
                }
                if (dup2(fd, STDOUT_FILENO) == -1)
                {
                    perror("dup2 outfile");
                    close(fd);
                    _exit(EXIT_FAILURE);
                }
                close(fd);
            }
            if (err_to_fd >= 0)
            {
                if (dup2(err_to_fd, STDERR_FILENO) == -1)
                {
                    perror("dup2 stderr->fd");
                    _exit(EXIT_FAILURE);
                }
            }
            if (errfile)
            {
                int fd = open(errfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
                if (fd < 0)
                {
                    perror("open errfile");
                    _exit(EXIT_FAILURE);
                }
                if (dup2(fd, STDERR_FILENO) == -1)
                {
                    perror("dup2 errfile");
                    close(fd);
                    _exit(EXIT_FAILURE);
                }
                close(fd);
            }
        }

        execvp(exec_argv[0], exec_argv);
        perror("execvp");
        _exit(EXIT_FAILURE);
    }
    else
    {
        /* parent */
        if (background)
        {
            /* add to jobs */
            job_t *j =
                job_add(child, child, orig_cmdline ? orig_cmdline : exec_argv[0], JOB_RUNNING);
            if (j)
                printf("[bg] child started: %d (job %d)\n", (int) child, j->id);
            else
                printf("[bg] child started: %d\n", (int) child);
            /* don't wait; SIGCHLD will notify */
        }
        else
        {
            do
            {
                waitpid(child, &status, WUNTRACED);
            }
            while (!WIFEXITED(status) && !WIFSIGNALED(status));
        }
    }

    for (size_t i = 0; exec_argv[i] != NULL; i++)
        free(exec_argv[i]);
    free(exec_argv);
    if (infile)
        free(infile);
    if (outfile)
        free(outfile);
    if (errfile)
        free(errfile);
    return 1;
}

/* ---------- Pipeline runner (supports background, minimal job tracking) ---------- */
/* This version forks each segment, connects pipes. For background pipelines we track leader pid as
 * first child. */
static int run_pipeline_core(char **argv, int background, const char *orig_cmdline)
{
    /* Count segments */
    int segments = 1;
    for (int i = 0; argv[i] != NULL; i++)
        if (strcmp(argv[i], "|") == 0)
            segments++;
    /* split into segments into seg_argvs like before */
    char ***seg_argvs = malloc((size_t) segments * sizeof(char **));
    int *seg_lengths = malloc((size_t) segments * sizeof(int));
    if (!seg_argvs || !seg_lengths)
    {
        fprintf(stderr, "Allocation error\n");
        free(seg_argvs);
        free(seg_lengths);
        return 1;
    }
    int idx = 0;
    for (int s = 0; s < segments; s++)
    {
        int len = 0;
        while (argv[idx] != NULL && strcmp(argv[idx], "|") != 0)
        {
            len++;
            idx++;
        }
        seg_lengths[s] = len;
        seg_argvs[s] = malloc((size_t) (len + 1) * sizeof(char *));
        if (!seg_argvs[s])
        {
            for (int k = 0; k < s; k++)
                free(seg_argvs[k]);
            free(seg_argvs);
            free(seg_lengths);
            return 1;
        }
        int start = idx - len;
        for (int k = 0; k < len; k++)
            seg_argvs[s][k] = argv[start + k];
        seg_argvs[s][len] = NULL;
        if (argv[idx] != NULL && strcmp(argv[idx], "|") == 0)
            idx++;
    }

    /* prepare exec argv for each segment and redir info */
    char ***exec_av = malloc((size_t) segments * sizeof(char **));
    for (int i = 0; i < segments; i++)
        exec_av[i] = NULL;
    char **infile = calloc((size_t) segments, sizeof(char *));
    char **outfile = calloc((size_t) segments, sizeof(char *));
    char **errfile = calloc((size_t) segments, sizeof(char *));
    int *append_out = calloc((size_t) segments, sizeof(int));
    int *err_to_fd = calloc((size_t) segments, sizeof(int));
    int *out_to_fd = calloc((size_t) segments, sizeof(int));
    int *in_from_fd = calloc((size_t) segments, sizeof(int));
    int *out_and_err = calloc((size_t) segments, sizeof(int));
    if (!infile || !outfile || !errfile || !append_out || !err_to_fd || !out_to_fd || !in_from_fd ||
        !out_and_err)
        goto pipeline_cleanup1;

    for (int s = 0; s < segments; s++)
    {
        exec_av[s] = strip_redirection_and_get_files(
            seg_argvs[s], &infile[s], &outfile[s], &errfile[s], &append_out[s], &err_to_fd[s],
            &out_to_fd[s], &in_from_fd[s], &out_and_err[s]);
        if (!exec_av[s])
        {
            fprintf(stderr, "Syntax/allocation error parsing redirections in pipeline segment %d\n",
                    s);
            goto pipeline_cleanup1;
        }
        if (exec_av[s][0] == NULL)
        {
            fprintf(stderr, "Error: no command specified in pipeline segment %d\n", s);
            goto pipeline_cleanup1;
        }
    }

    int npipes = segments - 1;
    int (*pipes)[2] = NULL;
    if (npipes > 0)
    {
        pipes = malloc((size_t) npipes * sizeof(int[2]));
        if (!pipes)
        {
            perror("malloc pipes");
            goto pipeline_cleanup1;
        }
        for (int p = 0; p < npipes; p++)
        {
            if (pipe(pipes[p]) == -1)
            {
                perror("pipe");
                for (int q = 0; q < p; q++)
                {
                    close(pipes[q][0]);
                    close(pipes[q][1]);
                }
                goto pipeline_cleanup1;
            }
        }
    }

    pid_t *pids = malloc((size_t) segments * sizeof(pid_t));
    if (!pids)
    {
        perror("malloc pids");
        goto pipeline_cleanup2;
    }
    for (int i = 0; i < segments; i++)
        pids[i] = -1;

    pid_t leader = -1;
    for (int s = 0; s < segments; s++)
    {
        pid_t pid = fork();
        if (pid == -1)
        {
            perror("fork");
            pids[s] = -1;
            continue;
        }
        else if (pid == 0)
        {
            /* child restore default SIGINT */
            signal(SIGINT, SIG_DFL);
            if (s > 0)
            {
                if (dup2(pipes[s - 1][0], STDIN_FILENO) == -1)
                {
                    perror("dup2 pipe->stdin");
                    _exit(EXIT_FAILURE);
                }
            }
            if (s < segments - 1)
            {
                if (dup2(pipes[s][1], STDOUT_FILENO) == -1)
                {
                    perror("dup2 stdout->pipe");
                    _exit(EXIT_FAILURE);
                }
            }
            for (int p = 0; p < npipes; p++)
            {
                close(pipes[p][0]);
                close(pipes[p][1]);
            }
            /* redirections like launch */
            if (in_from_fd[s] >= 0)
            {
                if (dup2(in_from_fd[s], STDIN_FILENO) == -1)
                {
                    perror("dup2 stdin from fd");
                    _exit(EXIT_FAILURE);
                }
            }
            if (infile[s])
            {
                int fd = open(infile[s], O_RDONLY);
                if (fd < 0)
                {
                    perror("open infile");
                    _exit(EXIT_FAILURE);
                }
                if (dup2(fd, STDIN_FILENO) == -1)
                {
                    perror("dup2 infile");
                    close(fd);
                    _exit(EXIT_FAILURE);
                }
                close(fd);
            }
            if (outfile[s] && out_and_err[s])
            {
                int flags = O_WRONLY | O_CREAT;
                if (append_out[s])
                    flags |= O_APPEND;
                else
                    flags |= O_TRUNC;
                int fd = open(outfile[s], flags, 0644);
                if (fd < 0)
                {
                    perror("open outfile for &>");
                    _exit(EXIT_FAILURE);
                }
                if (dup2(fd, STDOUT_FILENO) == -1)
                {
                    perror("dup2 outfile");
                    close(fd);
                    _exit(EXIT_FAILURE);
                }
                if (dup2(fd, STDERR_FILENO) == -1)
                {
                    perror("dup2 outfile->stderr");
                    close(fd);
                    _exit(EXIT_FAILURE);
                }
                close(fd);
            }
            else
            {
                if (out_to_fd[s] >= 0)
                {
                    if (dup2(out_to_fd[s], STDOUT_FILENO) == -1)
                    {
                        perror("dup2 stdout->fd");
                        _exit(EXIT_FAILURE);
                    }
                }
                if (outfile[s])
                {
                    int flags = O_WRONLY | O_CREAT;
                    if (append_out[s])
                        flags |= O_APPEND;
                    else
                        flags |= O_TRUNC;
                    int fd = open(outfile[s], flags, 0644);
                    if (fd < 0)
                    {
                        perror("open outfile");
                        _exit(EXIT_FAILURE);
                    }
                    if (dup2(fd, STDOUT_FILENO) == -1)
                    {
                        perror("dup2 outfile");
                        close(fd);
                        _exit(EXIT_FAILURE);
                    }
                    close(fd);
                }
                if (err_to_fd[s] >= 0)
                {
                    if (dup2(err_to_fd[s], STDERR_FILENO) == -1)
                    {
                        perror("dup2 stderr->fd");
                        _exit(EXIT_FAILURE);
                    }
                }
                if (errfile[s])
                {
                    int fd = open(errfile[s], O_WRONLY | O_CREAT | O_TRUNC, 0644);
                    if (fd < 0)
                    {
                        perror("open errfile");
                        _exit(EXIT_FAILURE);
                    }
                    if (dup2(fd, STDERR_FILENO) == -1)
                    {
                        perror("dup2 errfile");
                        close(fd);
                        _exit(EXIT_FAILURE);
                    }
                    close(fd);
                }
            }
            execvp(exec_av[s][0], exec_av[s]);
            perror("execvp");
            _exit(EXIT_FAILURE);
        }
        else
        {
            pids[s] = pid;
            if (leader == -1)
                leader = pid;
            /* parent continues */
        }
    }

    /* parent */
    for (int p = 0; p < npipes; p++)
    {
        close(pipes[p][0]);
        close(pipes[p][1]);
    }
    if (background)
    {
        job_t *j = job_add(leader, leader, orig_cmdline ? orig_cmdline : "(pipeline)", JOB_RUNNING);
        if (j)
            printf("[bg] pipeline started, leader pid: %d (job %d)\n", (int) leader, j->id);
        else
            printf("[bg] pipeline started, leader pid: %d\n", (int) leader);
        /* don't wait; SIGCHLD will notify */
    }
    else
    {
        int status;
        for (int s = 0; s < segments; s++)
        {
            if (pids[s] > 0)
                waitpid(pids[s], &status, 0);
        }
    }

    free(pids);

pipeline_cleanup2:
    if (pipes)
        free(pipes);
pipeline_cleanup1:
    if (exec_av)
    {
        for (int s = 0; s < segments; s++)
        {
            if (exec_av[s])
            {
                for (size_t x = 0; exec_av[s][x] != NULL; x++)
                    free(exec_av[s][x]);
                free(exec_av[s]);
            }
        }
        free(exec_av);
    }
    if (infile)
    {
        for (int s = 0; s < segments; s++)
            if (infile[s])
                free(infile[s]);
        free(infile);
    }
    if (outfile)
    {
        for (int s = 0; s < segments; s++)
            if (outfile[s])
                free(outfile[s]);
        free(outfile);
    }
    if (errfile)
    {
        for (int s = 0; s < segments; s++)
            if (errfile[s])
                free(errfile[s]);
        free(errfile);
    }
    if (append_out)
        free(append_out);
    if (err_to_fd)
        free(err_to_fd);
    if (out_to_fd)
        free(out_to_fd);
    if (in_from_fd)
        free(in_from_fd);
    if (out_and_err)
        free(out_and_err);
    for (int s = 0; s < segments; s++)
        if (seg_argvs[s])
            free(seg_argvs[s]);
    free(seg_argvs);
    free(seg_lengths);
    return 1;
}

/* ---------- Builtins: cd, help, exit, jobs, fg, bg, history ---------- */
static int shell_cd(char **argv)
{
    if (argv[1] == NULL)
    {
        fprintf(stderr, "cd: expected argument to \"cd\"\n");
        return 1;
    }
    if (chdir(argv[1]) != 0)
        perror("cd");
    return 1;
}
static int shell_help(char **argv)
{
    (void) argv;
    printf("Builtin Commands:\n cd help exit jobs fg bg history\n");
    return 1;
}
static int shell_exit(char **argv)
{
    (void) argv;
    return 0;
}

/* builtin fg: bring job to foreground (wait) -- supports syntax: fg %jobid or fg jobid */
static int shell_fg(char **argv)
{
    if (argv[1] == NULL)
    {
        fprintf(stderr, "fg: usage: fg %%jobid or fg jobid\n");
        return 1;
    }
    int id = 0;
    if (argv[1][0] == '%')
        id = atoi(argv[1] + 1);
    else
        id = atoi(argv[1]);
    job_t *j = job_find_by_id(id);
    if (!j)
    {
        fprintf(stderr, "fg: job %s not found\n", argv[1]);
        return 1;
    }
    /* send SIGCONT */
    if (kill(j->leader, SIGCONT) < 0)
        perror("kill(SIGCONT)");
    j->state = JOB_RUNNING;
    /* wait for leader to finish */
    int status;
    while (waitpid(j->leader, &status, 0) > 0)
    {
        if (WIFEXITED(status) || WIFSIGNALED(status))
            break;
    }
    /* mark done and remove */
    printf("fg: job %d (pid %d) finished\n", j->id, (int) j->leader);
    job_remove(j);
    return 1;
}

/* builtin bg: continue stopped job in background */
static int shell_bg(char **argv)
{
    if (argv[1] == NULL)
    {
        fprintf(stderr, "bg: usage: bg %%jobid or bg jobid\n");
        return 1;
    }
    int id = 0;
    if (argv[1][0] == '%')
        id = atoi(argv[1] + 1);
    else
        id = atoi(argv[1]);
    job_t *j = job_find_by_id(id);
    if (!j)
    {
        fprintf(stderr, "bg: job %s not found\n", argv[1]);
        return 1;
    }
    if (kill(j->leader, SIGCONT) < 0)
        perror("kill(SIGCONT)");
    j->state = JOB_RUNNING;
    printf("bg: job %d (pid %d) continued\n", j->id, (int) j->leader);
    return 1;
}

/* wrapper builtins list */
char *builtin_str[] = {"cd", "help", "exit", "jobs", "fg", "bg", "history"};
int (*builtin_func[])(char **) = {&shell_cd, &shell_help, &shell_exit,     &builtin_jobs,
                                  &shell_fg, &shell_bg,   &builtin_history};

int num_builtins(void)
{
    return (int) (sizeof(builtin_str) / sizeof(char *));
}

/* ---------- Executor / shell_execute ---------- */
/* detect trailing '&' (background) and remove token */
static int shell_execute(char **argv, const char *orig_line)
{
    if (argv[0] == NULL)
        return 1;
    /* process notifications collected */
    process_notifications();

    /* detect trailing '&' */
    int background = 0;
    int last = 0;
    while (argv[last] != NULL)
        last++;
    if (last > 0 && strcmp(argv[last - 1], "&") == 0)
    {
        background = 1;
        free(argv[last - 1]);
        argv[last - 1] = NULL;
    }

    /* builtin dispatch: support jobs/fg/bg/history specially */
    if (strcmp(argv[0], "jobs") == 0)
    {
        builtin_jobs(argv);
        return 1;
    }
    if (strcmp(argv[0], "fg") == 0)
    {
        return shell_fg(argv);
    }
    if (strcmp(argv[0], "bg") == 0)
    {
        return shell_bg(argv);
    }
    if (strcmp(argv[0], "history") == 0)
    {
        builtin_history(argv);
        return 1;
    }

    /* other builtins (cd/help/exit) - run in shell (foreground) normally.
       If the user appended '&' for these, we will run them in the shell (foreground),
       because e.g., cd in background doesn't affect parent shell's cwd. */
    for (int i = 0; i < num_builtins(); i++)
    {
        if (strcmp(argv[0], builtin_str[i]) == 0)
        {
            /* run builtin in shell - ignore requested background for side-effectful builtins */
            return builtin_func[i](argv);
        }
    }

    /* if a pipeline exists, run pipeline handler */
    for (int k = 0; argv[k] != NULL; k++)
    {
        if (strcmp(argv[k], "|") == 0)
        {
            return run_pipeline_core(argv, background, orig_line);
        }
    }

    /* else single command */
    return launch_command_and_redirect(argv, background, orig_line);
}

/* ---------- Main ---------- */
int main(void)
{
    if (init_signal_handlers() != 0)
    {
        fprintf(stderr, "Warning: failed to initialize signal handlers\n");
    }
    history_load();

    char *line;
    char **argv;
    while (1)
    {
        /* process any pending notifications before printing prompt */
        process_notifications();
        /* read_line prints the prompt itself now */
        line = read_line();
        if (!line)
        {
            printf("exiting\n");
            break;
        }
        /* add to history */
        history_add(line);
        argv = parse_line(line);
        if (!argv)
        {
            fprintf(stderr, "Error: failed to parse input\n");
            free(line);
            continue;
        }
        if (argv[0] == NULL)
        {
            free(argv);
            free(line);
            continue;
        }

        int status = shell_execute(argv, line);

        /* free argv */
        for (int i = 0; argv[i] != NULL; i++)
            free(argv[i]);
        free(argv);
        free(line);
        if (status == 0)
            break;
    }

    /* cleanup jobs & history */
    history_save();
    for (int i = 0; i < history_count; i++)
        if (history[i])
            free(history[i]);
    for (int i = 0; i < job_count; i++)
        if (jobs[i])
        {
            free(jobs[i]->cmdline);
            free(jobs[i]);
        }
    return 0;
}

/* ---------- Tokenization / parse_line ---------- */
/* parse_line: tokenization (quotes, escapes, redirection tokens, '|') */
char **parse_line(char *line)
{
    int buf_size = TOKEN_BUF_SIZE;
    int position = 0;
    char **tokens = malloc((size_t) buf_size * sizeof(char *));
    if (!tokens)
        return NULL;
    size_t tok_buf = 128;
    char *current_token = malloc(tok_buf);
    if (!current_token)
    {
        free(tokens);
        return NULL;
    }
    size_t len = 0;
    int i = 0;
    int in_quotes = 0;
#define PUSH_CUR_TOKEN()                                                                           \
    do                                                                                             \
    {                                                                                              \
        if (len > 0)                                                                               \
        {                                                                                          \
            current_token[len] = '\0';                                                             \
            char *to = safe_strdup_or_null(current_token);                                         \
            if (!to)                                                                               \
            {                                                                                      \
                for (int k = 0; k < position; k++)                                                 \
                    free(tokens[k]);                                                               \
                free(tokens);                                                                      \
                free(current_token);                                                               \
                return NULL;                                                                       \
            }                                                                                      \
            tokens[position++] = to;                                                               \
            if (position >= buf_size)                                                              \
            {                                                                                      \
                buf_size += TOKEN_BUF_SIZE;                                                        \
                char **tmp = realloc(tokens, (size_t) buf_size * sizeof(char *));                  \
                if (!tmp)                                                                          \
                {                                                                                  \
                    for (int k = 0; k < position; k++)                                             \
                        free(tokens[k]);                                                           \
                    free(tokens);                                                                  \
                    free(current_token);                                                           \
                    return NULL;                                                                   \
                }                                                                                  \
                tokens = tmp;                                                                      \
            }                                                                                      \
            len = 0;                                                                               \
        }                                                                                          \
    }                                                                                              \
    while (0)

    while (line[i] != '\0')
    {
        char c = line[i];
        if (c == '"')
        {
            in_quotes = !in_quotes;
            i++;
            continue;
        }
        if (c == '\\')
        {
            if (line[i + 1] != '\0')
            {
                i++;
                c = line[i];
            }
            else
            {
                i++;
                continue;
            }
        }
        if (!in_quotes)
        {
            if (c == '&' && line[i + 1] == '>' && line[i + 2] == '>')
            {
                char *t = safe_strdup_or_null("&>>");
                if (!t)
                {
                    for (int k = 0; k < position; k++)
                        free(tokens[k]);
                    free(tokens);
                    free(current_token);
                    return NULL;
                }
                PUSH_CUR_TOKEN();
                tokens[position++] = t;
                i += 3;
                continue;
            }
            if (c == '&' && line[i + 1] == '>')
            {
                char *t = safe_strdup_or_null("&>");
                if (!t)
                {
                    for (int k = 0; k < position; k++)
                        free(tokens[k]);
                    free(tokens);
                    free(current_token);
                    return NULL;
                }
                PUSH_CUR_TOKEN();
                tokens[position++] = t;
                i += 2;
                continue;
            }
            if (c == '>' && line[i + 1] == '>')
            {
                PUSH_CUR_TOKEN();
                char *t = safe_strdup_or_null(">>");
                if (!t)
                {
                    for (int k = 0; k < position; k++)
                        free(tokens[k]);
                    free(tokens);
                    free(current_token);
                    return NULL;
                }
                tokens[position++] = t;
                i += 2;
                continue;
            }
            if (c == '>' || c == '<')
            {
                PUSH_CUR_TOKEN();
                char single[2];
                single[0] = c;
                single[1] = '\0';
                char *t = safe_strdup_or_null(single);
                if (!t)
                {
                    for (int k = 0; k < position; k++)
                        free(tokens[k]);
                    free(tokens);
                    free(current_token);
                    return NULL;
                }
                tokens[position++] = t;
                i++;
                if (line[i] == '&' && isdigit((unsigned char) line[i + 1]))
                {
                    int start = i + 1;
                    int j = start;
                    while (line[j] != '\0' && isdigit((unsigned char) line[j]))
                        j++;
                    int nd = j - start;
                    char *special = malloc((size_t) nd + 2);
                    if (!special)
                    {
                        for (int k = 0; k < position; k++)
                            free(tokens[k]);
                        free(tokens);
                        free(current_token);
                        return NULL;
                    }
                    special[0] = '&';
                    memcpy(special + 1, &line[start], (size_t) nd);
                    special[nd + 1] = '\0';
                    char *t2 = safe_strdup_or_null(special);
                    free(special);
                    if (!t2)
                    {
                        for (int k = 0; k < position; k++)
                            free(tokens[k]);
                        free(tokens);
                        free(current_token);
                        return NULL;
                    }
                    tokens[position++] = t2;
                    i = j;
                }
                continue;
            }
            if (isdigit((unsigned char) c) && line[i + 1] == '>')
            {
                PUSH_CUR_TOKEN();
                int start = i;
                int j = start;
                while (line[j] != '\0' && isdigit((unsigned char) line[j]))
                    j++;
                if (line[j] == '>')
                {
                    int nd = j - start;
                    char *special = malloc((size_t) nd + 2);
                    if (!special)
                    {
                        for (int k = 0; k < position; k++)
                            free(tokens[k]);
                        free(tokens);
                        free(current_token);
                        return NULL;
                    }
                    memcpy(special, &line[start], (size_t) nd);
                    special[nd] = '>';
                    special[nd + 1] = '\0';
                    char *t = safe_strdup_or_null(special);
                    free(special);
                    if (!t)
                    {
                        for (int k = 0; k < position; k++)
                            free(tokens[k]);
                        free(tokens);
                        free(current_token);
                        return NULL;
                    }
                    tokens[position++] = t;
                    i = j + 1;
                    continue;
                }
            }
            if (c == '&' && isdigit((unsigned char) line[i + 1]))
            {
                PUSH_CUR_TOKEN();
                int start = i + 1;
                int j = start;
                while (line[j] != '\0' && isdigit((unsigned char) line[j]))
                    j++;
                int nd = j - start;
                char *special = malloc((size_t) nd + 2);
                if (!special)
                {
                    for (int k = 0; k < position; k++)
                        free(tokens[k]);
                    free(tokens);
                    free(current_token);
                    return NULL;
                }
                special[0] = '&';
                memcpy(special + 1, &line[start], (size_t) nd);
                special[nd + 1] = '\0';
                char *t = safe_strdup_or_null(special);
                free(special);
                if (!t)
                {
                    for (int k = 0; k < position; k++)
                        free(tokens[k]);
                    free(tokens);
                    free(current_token);
                    return NULL;
                }
                tokens[position++] = t;
                i = j;
                continue;
            }
            if (c == '|')
            {
                PUSH_CUR_TOKEN();
                char *t = safe_strdup_or_null("|");
                if (!t)
                {
                    for (int k = 0; k < position; k++)
                        free(tokens[k]);
                    free(tokens);
                    free(current_token);
                    return NULL;
                }
                tokens[position++] = t;
                i++;
                continue;
            }
        }
        if (!in_quotes && (c == ' ' || c == '\t' || c == '\n'))
        {
            PUSH_CUR_TOKEN();
            i++;
            continue;
        }
        if (len + 1 >= tok_buf)
        {
            tok_buf *= 2;
            char *tmp = realloc(current_token, tok_buf);
            if (!tmp)
            {
                for (int k = 0; k < position; k++)
                    free(tokens[k]);
                free(tokens);
                free(current_token);
                return NULL;
            }
            current_token = tmp;
        }
        current_token[len++] = c;
        i++;
    }
    if (len > 0)
    {
        current_token[len] = '\0';
        char *token = safe_strdup_or_null(current_token);
        if (!token)
        {
            for (int k = 0; k < position; k++)
                free(tokens[k]);
            free(tokens);
            free(current_token);
            return NULL;
        }
        tokens[position++] = token;
    }
    tokens[position] = NULL;
    free(current_token);
    return tokens;
}
