/*
 * SimPoint PC Counter Plugin
 * 
 * Tracks PC execution counts per interval for SimPoint correlation analysis.
 * Outputs all PCs executed in each interval with their execution counts.
 */
#include <qemu-plugin.h>

#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <glib.h>

#define DEFAULT_INTERVAL_SIZE 1000000000  /* 1B instructions */
#define MAX_TARGET_INTERVALS 100

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

typedef struct {
    uint64_t pc;
    uint64_t exec_count;
    size_t insns;  /* Instructions in this TB */
} PCCount;

/* Configuration */
static qemu_plugin_id_t plugin_id;
static uint64_t interval_size = DEFAULT_INTERVAL_SIZE;
static bool track_all_intervals = true;
static uint64_t target_intervals[MAX_TARGET_INTERVALS];
static int num_target_intervals = 0;
static uint64_t trigger_pc = 0;

/* Tracking state */
static GHashTable *pc_counts = NULL;
static uint64_t inst_count = 0;
static uint64_t total_inst_count = 0;
static uint64_t completed_intervals = 0;
static uint64_t interval_drift = 0;
static bool plugin_active = true;
static bool tracking_enabled = false;  /* Start disabled if trigger_pc is set */

/* Output */
static FILE *output_file = NULL;

/* User address check */
static inline bool is_user_address(uint64_t pc)
{
    return (pc < 0x8000000000000000ULL);
}

/* Check if we should dump this interval */
static bool should_dump_interval(uint64_t interval_num)
{
    if (track_all_intervals) {
        return true;
    }
    
    for (int i = 0; i < num_target_intervals; i++) {
        if (target_intervals[i] == interval_num) {
            return true;
        }
    }
    
    return false;
}

/* Dump PC counts for current interval */
/* Reset all PC counts to zero */
static void reset_pc_counts(void)
{
    GHashTableIter iter;
    gpointer key, value;
    
    g_hash_table_iter_init(&iter, pc_counts);
    
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        PCCount *pc_cnt = (PCCount *)value;
        pc_cnt->exec_count = 0;  /* Just reset, don't free */
    }
}

/* Dump PC counts for current interval */
static void dump_interval_pcs(void)
{
    if (!should_dump_interval(completed_intervals)) {
        /* Skip this interval - just reset counts */
        reset_pc_counts();
        return;
    }
    
    GHashTableIter iter;
    gpointer key, value;
    
    g_hash_table_iter_init(&iter, pc_counts);
    
    uint64_t total_pcs = 0;
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        PCCount *pc_cnt = (PCCount *)value;
        
        if (pc_cnt->exec_count > 0) {
            fprintf(output_file, "Interval:%"PRIu64":0x%"PRIx64":%"PRIu64"\n",
                    completed_intervals, pc_cnt->pc, pc_cnt->exec_count);
            total_pcs++;
        }
    }
    
    /* Periodic status and flush */
    if (completed_intervals % 10 == 0) {
        fprintf(stderr, "PC_COUNTER: Completed %"PRIu64" intervals (%.2fB instructions), %"PRIu64" unique PCs\n",
                completed_intervals, total_inst_count / 1e9, total_pcs);
        fflush(output_file);
    }
    
    /* Reset counts for next interval - DON'T destroy hash table! */
    reset_pc_counts();
}

/* Check for interval boundary */
static void check_interval(unsigned int cpu_index, void *udata)
{
    if (!plugin_active) {
        return;
    }
    
    /* Handle interval drift like gem5 */
    while (inst_count + interval_drift >= interval_size) {
        dump_interval_pcs();
        
        /* Calculate drift for next interval */
        interval_drift = (inst_count + interval_drift) - interval_size;
        inst_count = 0;
        completed_intervals++;
    }
}

/* Plugin exit handler */
static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    /* Dump final interval if any instructions remain */
    if (inst_count > 0) {
        dump_interval_pcs();
        completed_intervals++;
    }
    
    fprintf(stderr, "PC_COUNTER: Exiting. Total instructions: %"PRIu64"\n", total_inst_count);
    fprintf(stderr, "PC_COUNTER: Completed intervals: %"PRIu64"\n", completed_intervals);
    
    if (pc_counts) {
        g_hash_table_destroy(pc_counts);
    }
    
    if (output_file) {
        fclose(output_file);
    }
}

/* Initialize plugin */
static void plugin_init(const char *bench_name)
{
    char *output_file_name = g_strdup_printf("%s.pc_counts.txt", bench_name);
    
    output_file = fopen(output_file_name, "w");
    
    if (!output_file) {
        fprintf(stderr, "PC_COUNTER: ERROR - Failed to open output file: %s\n", 
                output_file_name);
        exit(1);
    }
    
    /* Write header */
    fprintf(output_file, "# SimPoint PC Count Data\n");
    fprintf(output_file, "# Format: Interval:N:PC:Count\n");
    fprintf(output_file, "# Interval_size: %"PRIu64" instructions\n", interval_size);
    
    if (trigger_pc != 0) {
        fprintf(output_file, "# Trigger PC: 0x%"PRIx64"\n", trigger_pc);
    }
    
    if (!track_all_intervals) {
        fprintf(output_file, "# Tracking specific intervals: ");
        for (int i = 0; i < num_target_intervals; i++) {
            fprintf(output_file, "%"PRIu64" ", target_intervals[i]);
        }
        fprintf(output_file, "\n");
    }
    
    fprintf(output_file, "#\n");
    
    g_free(output_file_name);
    
    /* Create hash table: PC (as pointer) -> PCCount struct */
    pc_counts = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
    
    fprintf(stderr, "PC_COUNTER: Initialized\n");
    fprintf(stderr, "PC_COUNTER: Interval size: %"PRIu64" instructions\n", interval_size);
    
    if (trigger_pc != 0) {
        fprintf(stderr, "PC_COUNTER: Will start tracking at PC 0x%"PRIx64"\n", trigger_pc);
    }
    
    fprintf(stderr, "PC_COUNTER: Track all intervals: %s\n", 
            track_all_intervals ? "yes" : "no");
    
    if (!track_all_intervals) {
        fprintf(stderr, "PC_COUNTER: Target intervals: ");
        for (int i = 0; i < num_target_intervals; i++) {
            fprintf(stderr, "%"PRIu64" ", target_intervals[i]);
        }
        fprintf(stderr, "\n");
    }
}

/* TB translation callback */
static void tb_record(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    uint64_t pc = qemu_plugin_tb_vaddr(tb);
    size_t insns = qemu_plugin_tb_n_insns(tb);
    
    if (!plugin_active) {
        return;
    }
    
    if (!is_user_address(pc)) {
        return;
    }
    
    /* Check for trigger PC - same logic as BBV plugin */
    if (trigger_pc != 0 && !tracking_enabled) {
        if (pc == trigger_pc) {
            tracking_enabled = true;
            fprintf(stderr, "PC_COUNTER: Started tracking at PC 0x%"PRIx64"\n", pc);
        } else {
            return;  /* Skip until we hit trigger PC */
        }
    }
    
    /* Look up or create PC count entry */
    PCCount *cnt = (PCCount *)g_hash_table_lookup(pc_counts, (gpointer)pc);
    
    if (!cnt) {
        cnt = g_new0(PCCount, 1);
        cnt->pc = pc;
        cnt->exec_count = 0;
        cnt->insns = insns;
        
        g_hash_table_insert(pc_counts, (gpointer)pc, cnt);
    }
    
    /* Register inline counters */
    qemu_plugin_register_vcpu_tb_exec_inline(tb, QEMU_PLUGIN_INLINE_ADD_U64,
                                             &cnt->exec_count, 1);
    qemu_plugin_register_vcpu_tb_exec_inline(tb, QEMU_PLUGIN_INLINE_ADD_U64,
                                             &inst_count, insns);
    qemu_plugin_register_vcpu_tb_exec_inline(tb, QEMU_PLUGIN_INLINE_ADD_U64,
                                             &total_inst_count, insns);
    
    /* Check for interval boundary */
    qemu_plugin_register_vcpu_tb_exec_cb(tb, check_interval,
                                         QEMU_PLUGIN_CB_NO_REGS, NULL);
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    const char *bench_name = "trace";
    
    plugin_id = id;
    
    if (argc > 0) {
        bench_name = argv[0];
    }
    
    /* Parse trigger PC - same as BBV plugin */
    if (argc > 1) {
        trigger_pc = strtoull(argv[1], NULL, 0);
        if (trigger_pc != 0) {
            tracking_enabled = false;
            fprintf(stderr, "PC_COUNTER: Will start tracking at PC 0x%"PRIx64"\n", trigger_pc);
        } else {
            tracking_enabled = true;
        }
    } else {
        trigger_pc = 0;
        tracking_enabled = true;
    }
    
    /* Parse interval size - same as BBV plugin */
    if (argc > 2) {
        interval_size = strtoull(argv[2], NULL, 0);
        if (interval_size == 0) {
            fprintf(stderr, "PC_COUNTER: Invalid interval size, using default\n");
            interval_size = DEFAULT_INTERVAL_SIZE;
        } else {
            fprintf(stderr, "PC_COUNTER: Interval size: %"PRIu64" instructions\n", interval_size);
        }
    }
    
    /* Parse target intervals - starting from argv[3] onwards */
    for (int i = 3; i < argc; i++) {
        uint64_t interval_num = strtoull(argv[i], NULL, 0);
        if (num_target_intervals < MAX_TARGET_INTERVALS) {
            target_intervals[num_target_intervals++] = interval_num;
            track_all_intervals = false;
        } else {
            fprintf(stderr, "PC_COUNTER: WARNING - Too many target intervals, ignoring %s\n", 
                    argv[i]);
        }
    }
    
    plugin_init(bench_name);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_record);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    
    fprintf(stderr, "PC_COUNTER: Drift handling enabled\n");
    
    return 0;
}