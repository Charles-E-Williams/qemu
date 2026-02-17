/*
 * Logging support
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/range.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "qemu/cutils.h"
#include "qemu/log_instr.h"
#include "trace/control.h"
#include "qemu/thread.h"
#include "qemu/lockable.h"

static char *logfilename;
static QemuMutex qemu_logfile_mutex;
QemuLogFile *qemu_logfile;
int qemu_loglevel;
static int log_append = 0;
GArray *debug_regions;
GArray *simpoints;
GArray *adjusted_simpoints;
GArray *warmup_duration;
GArray *simpoint_pcs;       
uint64_t INTERVAL_SIZE;
uint64_t WARMUP_INTERVAL;
uint64_t START_PC = 0;

/* Return the number of characters emitted.  */
int qemu_log(const char *fmt, ...)
{
    int ret = 0;
    QemuLogFile *logfile;

    rcu_read_lock();
    logfile = qatomic_rcu_read(&qemu_logfile);
    if (logfile) {
        va_list ap;
        va_start(ap, fmt);
        ret = vfprintf(logfile->fd, fmt, ap);
        va_end(ap);

        /* Don't pass back error results.  */
        if (ret < 0) {
            ret = 0;
        }
    }
    rcu_read_unlock();
    return ret;
}

static void __attribute__((__constructor__)) qemu_logfile_init(void)
{
    qemu_mutex_init(&qemu_logfile_mutex);
}

static void qemu_logfile_free(QemuLogFile *logfile)
{
    g_assert(logfile);

    if (logfile->fd != stderr) {
        fclose(logfile->fd);
    }
    g_free(logfile);
}

static bool log_uses_own_buffers;

__attribute__((weak)) int qemu_log_instr_global_switch(int log_flags);
__attribute__((weak)) int qemu_log_instr_global_switch(int log_flags)
{
    /* Real implementation in accel/tcg/log_instr.c. */
    return log_flags;
}

/* enable or disable low levels log */
void qemu_set_log_internal(int log_flags)
{
    bool need_to_open_file = false;
    QemuLogFile *logfile;

    qemu_loglevel = log_flags;

#ifdef CONFIG_TRACE_LOG
    qemu_loglevel |= LOG_TRACE;
#endif
    /*
     * In all cases we only log if qemu_loglevel is set.
     * Also:
     *   If not daemonized we will always log either to stderr
     *     or to a file (if there is a logfilename).
     *   If we are daemonized,
     *     we will only log if there is a logfilename.
     */
    if (qemu_loglevel && (!is_daemonized() || logfilename)) {
        need_to_open_file = true;
    }
    QEMU_LOCK_GUARD(&qemu_logfile_mutex);
    if (qemu_logfile && !need_to_open_file) {
        logfile = qemu_logfile;
        qatomic_rcu_set(&qemu_logfile, NULL);
        call_rcu(logfile, qemu_logfile_free, rcu);
    } else if (!qemu_logfile && need_to_open_file) {
        logfile = g_new0(QemuLogFile, 1);
        if (logfilename) {
            logfile->fd = fopen(logfilename, log_append ? "a" : "w");
            if (!logfile->fd) {
                g_free(logfile);
                perror(logfilename);
                qemu_log_close();
                return;
            }
            /* In case we are a daemon redirect stderr to logfile */
            if (is_daemonized()) {
                dup2(fileno(logfile->fd), STDERR_FILENO);
                fclose(logfile->fd);
                /* This will skip closing logfile in qemu_log_close() */
                logfile->fd = stderr;
            }
        } else {
            /* Default to stderr if no log file specified */
            assert(!is_daemonized());
            logfile->fd = stderr;
        }
        /* must avoid mmap() usage of glibc by setting a buffer "by hand" */
        if (log_uses_own_buffers) {
            static char logfile_buf[4096];

            setvbuf(logfile->fd, logfile_buf, _IOLBF, sizeof(logfile_buf));
        } else {
#if defined(_WIN32)
            /* Win32 doesn't support line-buffering, so use unbuffered output. */
            setvbuf(logfile->fd, NULL, _IONBF, 0);
#else
            setvbuf(logfile->fd, NULL, _IOLBF, 0);
#endif
            log_append = 1;
        }
        qatomic_rcu_set(&qemu_logfile, logfile);
    }
}

#ifdef CONFIG_TCG_LOG_INSTR
void qemu_set_log(int log_flags) {
    log_flags = qemu_log_instr_global_switch(log_flags);
    qemu_set_log_internal(log_flags);
}
#else
void qemu_set_log(int log_flags) { qemu_set_log_internal(log_flags); }
#endif

void qemu_log_needs_buffers(void)
{
    log_uses_own_buffers = true;
}

/*
 * Allow the user to include %d in their logfile which will be
 * substituted with the current PID. This is useful for debugging many
 * nested linux-user tasks but will result in lots of logs.
 *
 * filename may be NULL. In that case, log output is sent to stderr
 */
void qemu_set_log_filename(const char *filename, Error **errp)
{
    g_free(logfilename);
    logfilename = NULL;

    if (filename) {
            char *pidstr = strstr(filename, "%");
            if (pidstr) {
                /* We only accept one %d, no other format strings */
                if (pidstr[1] != 'd' || strchr(pidstr + 2, '%')) {
                    error_setg(errp, "Bad logfile format: %s", filename);
                    return;
                } else {
                    logfilename = g_strdup_printf(filename, getpid());
                }
            } else {
                logfilename = g_strdup(filename);
            }
    }

    qemu_log_close();
    qemu_set_log(qemu_loglevel);
    if (!qemu_logfile) {
        error_setg(errp, "Failed to open logfile: %s", filename);
    }
}

/* Returns true if addr is in our debug filter or no filter defined
 */
bool qemu_log_in_addr_range(uint64_t addr)
{
    if (debug_regions) {
        int i = 0;
        for (i = 0; i < debug_regions->len; i++) {
            Range *range = &g_array_index(debug_regions, Range, i);
            if (range_contains(range, addr)) {
                return true;
            }
        }
        return false;
    } else {
        return true;
    }
}


void qemu_set_simpoints(const char* simpoints_arg, Error **errp)
{
    gchar **args = g_strsplit(simpoints_arg, ",", -1);
    g_autoptr(GError) err = NULL;
    char* filename = NULL;
    uint64_t interval = 1000000000; /* 1 Billion instructions by default */
    gchar* file_contents = NULL;
    gchar** lines = NULL;
    uint64_t warmup = 0;
    const char* format = "interval";  /* Default to interval format */
    uint64_t start_pc = 0;

    /* Parse arguments */
    for (int i = 0; args[i]; i++) {
        gchar** kv = g_strsplit(args[i], "=", 2);
        if (kv[0] && kv[1]) {
            if (strcmp(kv[0], "file") == 0) {
                filename = g_strdup(kv[1]);
            } else if (strcmp(kv[0], "interval") == 0) {
                if (qemu_strtou64(kv[1], NULL, 10, &interval)) {
                    error_setg(errp, "Invalid interval size input");
                    g_strfreev(kv);
                    goto out;
                }
            } else if (strcmp(kv[0], "warmup") == 0) {
                if (qemu_strtou64(kv[1], NULL, 10, &warmup)) {
                    error_setg(errp, "Invalid warmup instructions input");
                    g_strfreev(kv);
                    goto out;
                }
            } else if (strcmp(kv[0], "format") == 0) {
                format = g_strdup(kv[1]);
            } else if (strcmp(kv[0], "start_pc") == 0) {
                if (qemu_strtou64(kv[1], NULL, 0, &start_pc)) {
                    error_setg(errp, "Invalid start_pc input");
                    g_strfreev(kv);
                    goto out;
                }
            } else {
                error_setg(errp, "Unknown option: %s", kv[0]);
                g_strfreev(kv);
                goto out;
            }  
        }
        g_strfreev(kv);
    }

    if (!filename) {
        error_setg(errp, "Missing filename");
        goto out;
    }

    if (!g_file_get_contents(filename, &file_contents, NULL, &err)) {
        error_setg(errp, "Could not read file: %s", err->message);
        goto out;
    }

    /* Clean up existing arrays */
    if (simpoints) {
        g_array_free(simpoints, TRUE);
        g_array_free(adjusted_simpoints, TRUE);
        g_array_free(warmup_duration, TRUE);
        simpoints = NULL;
        adjusted_simpoints = NULL;
        warmup_duration = NULL;
    }
    if (simpoint_pcs) {
        g_array_free(simpoint_pcs, TRUE);
        simpoint_pcs = NULL;
    }

    INTERVAL_SIZE = interval;
    WARMUP_INTERVAL = warmup;
    START_PC = start_pc; 

    lines = g_strsplit(file_contents, "\n", -1);
    
    if (strcmp(format, "pc") == 0) {
        /* PC-based format - NO warmup support */
        simpoint_pcs = g_array_new(FALSE, TRUE, sizeof(simpoint_pc_entry_t));
        
        for (int i = 0; lines[i] != NULL; i++) {
            gchar* line = g_strstrip(lines[i]);
            if (line[0] == '\0' || line[0] == '#') continue;
            
            simpoint_pc_entry_t entry;
            
            /* Format: PC execution_count */
            if (sscanf(line, "0x%" SCNx64 " %" SCNu64, 
                      &entry.pc, &entry.execution_count) != 2) {
                if (sscanf(line, "%" SCNx64 " %" SCNu64, 
                          &entry.pc, &entry.execution_count) != 2) {
                    error_setg(errp, "Invalid PC format line: %s", line);
                    goto out;
                }
            }
            
            /* No warmup adjustment for PC-based simpoints */
            g_array_append_val(simpoint_pcs, entry);
        }
        
        fprintf(stderr, "Loaded %d PC-based simpoints\n", 
                simpoint_pcs->len);
        
        if (warmup > 0) {
            fprintf(stderr, "Warning: warmup parameter ignored for PC-based simpoints\n");
        }
        
        if (start_pc != 0) {
            fprintf(stderr, "Tracing will begin at start_pc: 0x%lx\n", start_pc);
        }
        
    } else {
        /* Traditional interval-based format - your existing logic */
        simpoints = g_array_new(FALSE, TRUE, sizeof(uint64_t));
        adjusted_simpoints = g_array_new(FALSE, TRUE, sizeof(uint64_t));
        warmup_duration = g_array_new(FALSE, TRUE, sizeof(uint64_t));

        GArray *temp = g_array_new(FALSE, TRUE, sizeof(uint64_t));
        
        for (int i = 0; lines[i] != NULL; i++) {
            uint64_t interval_num;
            gchar* line = g_strstrip(lines[i]);
            
            if (line[0] == '\0' || line[0] == '#') continue;
            
            if (sscanf(line, "%" SCNu64, &interval_num) != 1) {
                error_setg(errp, "Invalid line format: %s", line);
                g_array_free(temp, TRUE);
                goto out;
            }
            
            g_array_append_val(temp, interval_num);
        }

        /* Calculate adjusted starts with warmup - your existing logic */
        for (int i = 0; i < temp->len; i++) {
            uint64_t interval_num = g_array_index(temp, uint64_t, i);
            uint64_t start = interval_num * INTERVAL_SIZE;
            uint64_t adjusted_start = start;
            uint64_t warmup_instr = 0;

            if (warmup) {
                if (i == 0) {
                    if (start > warmup) {
                        adjusted_start = start - warmup;
                        warmup_instr = warmup;
                    } else {
                        adjusted_start = 0;
                        warmup_instr = start;
                    }
                } else {
                    uint64_t prev_interval = g_array_index(temp, uint64_t, i-1);
                    uint64_t prev_end = (prev_interval + 1) * INTERVAL_SIZE;
                    uint64_t gap = start - prev_end;

                    if (warmup > gap) {
                        adjusted_start = prev_end;
                        warmup_instr = gap;
                    } else {
                        adjusted_start = start - warmup;
                        warmup_instr = warmup;
                    }
                }
            }

            g_array_append_val(simpoints, start);
            g_array_append_val(adjusted_simpoints, adjusted_start);
            g_array_append_val(warmup_duration, warmup_instr);
        }

        g_array_free(temp, TRUE);
        fprintf(stderr, "Loaded %d interval-based simpoints\n", simpoints->len);
        
        if (start_pc != 0) {
            fprintf(stderr, "Tracing will begin at start_pc: 0x%lx\n", start_pc);
        }
    }

out: 
    g_strfreev(args);
    g_strfreev(lines);
    g_free(file_contents);
    g_free(filename);
}
void qemu_set_dfilter_ranges(const char *filter_spec, Error **errp)
{
    gchar **ranges = g_strsplit(filter_spec, ",", 0);
    int i;

    if (debug_regions) {
        g_array_unref(debug_regions);
        debug_regions = NULL;
    }

    debug_regions = g_array_sized_new(FALSE, FALSE,
                                      sizeof(Range), g_strv_length(ranges));
    for (i = 0; ranges[i]; i++) {
        const char *r = ranges[i];
        const char *range_op, *r2, *e;
        uint64_t r1val, r2val, lob, upb;
        struct Range range;

        range_op = strstr(r, "-");
        r2 = range_op ? range_op + 1 : NULL;
        if (!range_op) {
            range_op = strstr(r, "+");
            r2 = range_op ? range_op + 1 : NULL;
        }
        if (!range_op) {
            range_op = strstr(r, "..");
            r2 = range_op ? range_op + 2 : NULL;
        }
        if (!range_op) {
            error_setg(errp, "Bad range specifier");
            goto out;
        }

        if (qemu_strtou64(r, &e, 0, &r1val)
            || e != range_op) {
            error_setg(errp, "Invalid number to the left of %.*s",
                       (int)(r2 - range_op), range_op);
            goto out;
        }
        if (qemu_strtou64(r2, NULL, 0, &r2val)) {
            error_setg(errp, "Invalid number to the right of %.*s",
                       (int)(r2 - range_op), range_op);
            goto out;
        }

        switch (*range_op) {
        case '+':
            lob = r1val;
            upb = r1val + r2val - 1;
            break;
        case '-':
            upb = r1val;
            lob = r1val - (r2val - 1);
            break;
        case '.':
            lob = r1val;
            upb = r2val;
            break;
        default:
            g_assert_not_reached();
        }
        if (lob > upb) {
            error_setg(errp, "Invalid range");
            goto out;
        }
        range_set_bounds(&range, lob, upb);
        g_array_append_val(debug_regions, range);
    }
out:
    g_strfreev(ranges);
}

/* fflush() the log file */
void qemu_log_flush(void)
{
    QemuLogFile *logfile;

    rcu_read_lock();
    logfile = qatomic_rcu_read(&qemu_logfile);
    if (logfile) {
        fflush(logfile->fd);
    }
    rcu_read_unlock();
}

/* Close the log file */
void qemu_log_close(void)
{
    QemuLogFile *logfile;

    qemu_mutex_lock(&qemu_logfile_mutex);
    logfile = qemu_logfile;

    if (logfile) {
        qatomic_rcu_set(&qemu_logfile, NULL);
        call_rcu(logfile, qemu_logfile_free, rcu);
    }
    qemu_mutex_unlock(&qemu_logfile_mutex);
}

/* clang-format off */
const QEMULogItem qemu_log_items[] = {
    { CPU_LOG_TB_OUT_ASM, "out_asm",
      "show generated host assembly code for each compiled TB" },
    { CPU_LOG_TB_IN_ASM, "in_asm",
      "show target assembly code for each compiled TB" },
    { CPU_LOG_TB_OP, "op",
      "show micro ops for each compiled TB" },
    { CPU_LOG_TB_OP_OPT, "op_opt",
      "show micro ops after optimization" },
    { CPU_LOG_TB_OP_IND, "op_ind",
      "show micro ops before indirect lowering" },
    { CPU_LOG_INT, "int",
      "show interrupts/exceptions in short format" },
    { CPU_LOG_EXEC, "exec",
      "show trace before each executed TB (lots of logs)" },
    { CPU_LOG_INSTR, "instr",
      "CHERI only: show executed instructions and changed CPU state" },
    { CPU_LOG_INSTR_U, "uinstr",
      "CHERI only: show executed instructions and changed CPU state (user)" },
    { CPU_LOG_GUEST_DEBUG_MSG, "guest_debug",
      "CHERI only: Print guest debug messages" },
    { CPU_LOG_CHERI_BOUNDS, "bounds",
      "CHERI only: Log out-of-bounds capability creation" },
    { CPU_LOG_TB_CPU, "cpu",
      "show CPU registers before entering a TB (lots of logs)" },
    { CPU_LOG_TB_FPU, "fpu",
      "include FPU registers in the 'cpu' logging" },
    { CPU_LOG_MMU, "mmu",
      "log MMU-related activities" },
    { CPU_LOG_PCALL, "pcall",
      "x86 only: show protected mode far calls/returns/exceptions" },
    { CPU_LOG_RESET, "cpu_reset",
      "show CPU state before CPU resets" },
    { LOG_UNIMP, "unimp",
      "log unimplemented functionality" },
    { LOG_GUEST_ERROR, "guest_errors",
      "log when the guest OS does something invalid (eg accessing a\n"
      "non-existent register)" },
    { CPU_LOG_PAGE, "page",
      "dump pages at beginning of user mode emulation" },
    { CPU_LOG_TB_NOCHAIN, "nochain",
      "do not chain compiled TBs so that \"exec\" and \"cpu\" show\n"
      "complete traces" },
#ifdef CONFIG_PLUGIN
    { CPU_LOG_PLUGIN, "plugin", "output from TCG plugins\n"},
#endif
    { LOG_STRACE, "strace",
      "log every user-mode syscall, its input, and its result" },
    { 0, NULL, NULL },
};
/* clang-format on */

/* takes a comma separated list of log masks. Return 0 if error. */
int qemu_str_to_log_mask(const char *str)
{
    const QEMULogItem *item;
    int mask = 0;
    char **parts = g_strsplit(str, ",", 0);
    char **tmp;

    for (tmp = parts; tmp && *tmp; tmp++) {
        if (g_str_equal(*tmp, "all")) {
            for (item = qemu_log_items; item->mask != 0; item++) {
                mask |= item->mask;
            }
#ifdef CONFIG_TRACE_LOG
        } else if (g_str_has_prefix(*tmp, "trace:") && (*tmp)[6] != '\0') {
            trace_enable_events((*tmp) + 6);
            mask |= LOG_TRACE;
#endif
        } else {
            for (item = qemu_log_items; item->mask != 0; item++) {
                if (g_str_equal(*tmp, item->name)) {
                    goto found;
                }
            }
            goto error;
        found:
            mask |= item->mask;
        }
    }

    g_strfreev(parts);
    return mask;

 error:
    g_strfreev(parts);
    return 0;
}

void qemu_print_log_usage(FILE *f)
{
    const QEMULogItem *item;
    fprintf(f, "Log items (comma separated):\n");
    for (item = qemu_log_items; item->mask != 0; item++) {
        fprintf(f, "%-15s %s\n", item->name, item->help);
    }
#ifdef CONFIG_TRACE_LOG
    fprintf(f, "trace:PATTERN   enable trace events\n");
    fprintf(f, "\nUse \"-d trace:help\" to get a list of trace events.\n\n");
#endif
}
