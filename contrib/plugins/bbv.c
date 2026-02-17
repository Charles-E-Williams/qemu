/*
 * SimPoint BBV Plugin - Simplified version matching upstream QEMU style
*/

#include <qemu-plugin.h>

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <glib.h>
#include <zlib.h>

#define DEFAULT_INTERVAL_SIZE 100000000ULL /* Default 100M instructions */

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

typedef struct {
    uint64_t pc;              /* Starting PC of this basic block */
    uint64_t weighted_count;  /* Accumulated (exec_count * n_insns) for current interval */
    uint64_t total_exec;      /* Total executions since start (for Start PC tracking) */
    uint64_t id;              /* Unique BB identifier for SimPoint */
    size_t   n_insns;         /* Number of instructions in this BB */
} BasicBlock;

/* Global state */
static GHashTable *bb_table = NULL;
static qemu_plugin_id_t plugin_id;

static uint64_t unique_bb_id = 0;
static uint64_t inst_count = 0;              
static uint64_t total_inst_count = 0;       
static uint64_t completed_intervals = 0;
static bool tracking_enabled = false;
static bool plugin_active = true;

/* Interval start tracking */
static bool interval_started = false;
static uint64_t interval_start_pc = 0;
static uint64_t interval_start_pc_exec = 0;

/* Configuration */
static uint64_t trigger_pc = 0;
static uint64_t stop_pc = 0;
static uint64_t interval_size = DEFAULT_INTERVAL_SIZE;

/* Output files */
static gzFile bbv_file = NULL;
static FILE *simpoints_interval_file = NULL;

static inline bool is_user_address(uint64_t pc)
{
    return (pc < 0x8000000000000000ULL);
}

static gint cmp_bb_weight(gconstpointer a, gconstpointer b)
{
    const BasicBlock *ba = (const BasicBlock *)a;
    const BasicBlock *bb = (const BasicBlock *)b;
    if (ba->weighted_count > bb->weighted_count) return -1;
    if (ba->weighted_count < bb->weighted_count) return 1;
    return 0;
}


static void process_interval(void)
{
    GList *blocks = g_hash_table_get_values(bb_table);
    GList *sorted = g_list_sort(blocks, cmp_bb_weight);
    GList *it;
    bool first = true;
    
    gzprintf(bbv_file, "T");
    
    for (it = sorted; it != NULL; it = it->next) {
        BasicBlock *bb = (BasicBlock *)it->data;
        
        if (bb->weighted_count > 0) {
            if (first) {
                gzprintf(bbv_file, ":%"PRIu64":%"PRIu64, 
                        bb->id, bb->weighted_count);
                first = false;
            } else {
                gzprintf(bbv_file, " :%"PRIu64":%"PRIu64, 
                        bb->id, bb->weighted_count);
            }
            bb->weighted_count = 0;
        }
    }
    
    gzprintf(bbv_file, "\n");
    
    fprintf(simpoints_interval_file, "# Interval %"PRIu64": StartPC=0x%"PRIx64" Count=%"PRIu64"\n",
            completed_intervals, interval_start_pc, interval_start_pc_exec);
    
    if ((completed_intervals % 10) == 0) {
        gzflush(bbv_file, Z_SYNC_FLUSH);
        fflush(simpoints_interval_file);
    }
    
    g_list_free(sorted);
    completed_intervals++;
    interval_started = false;
}


static void check_interval(unsigned int cpu_index, void *udata)
{
    if (!plugin_active) {
        return;
    }
    
    while (inst_count >= interval_size) {
        process_interval();
        inst_count -= interval_size;  // interval drift
    }
}


static void track_interval_start(unsigned int cpu_index, void *udata)
{
    BasicBlock *bb = (BasicBlock *)udata;
    
    if (!plugin_active || interval_started) {
        return;
    }
    
    interval_started = true;
    interval_start_pc = bb->pc;
    interval_start_pc_exec = bb->total_exec;
}


static void check_stop(unsigned int cpu_index, void *udata)
{
    uint64_t pc = (uint64_t)(uintptr_t)udata;
    
    if (!plugin_active) {
        return;
    }
    
    if (stop_pc != 0 && pc == stop_pc) {
        fprintf(stderr, "BBV: Stopped at PC 0x%"PRIx64"\n", stop_pc);
        fprintf(stderr, "BBV: Total instructions: %"PRIu64"\n", total_inst_count);
        fprintf(stderr, "BBV: Completed intervals: %"PRIu64"\n", completed_intervals);
        fprintf(stderr, "BBV: Discarding partial interval (%"PRIu64" instructions)\n", inst_count);
        
        plugin_active = false;
        tracking_enabled = false;
    }
}


static void tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    uint64_t pc = qemu_plugin_tb_vaddr(tb);
    size_t n_insns = qemu_plugin_tb_n_insns(tb);
    BasicBlock *bb;
    
    if (!plugin_active) {
        return;
    }
    
    if (!is_user_address(pc)) {
        return;
    }
    
    if (trigger_pc != 0 && !tracking_enabled) {
        if (pc == trigger_pc) {
            tracking_enabled = true;
            fprintf(stderr, "BBV: Started tracking at PC 0x%"PRIx64"\n", pc);
        } else {
            return;
        }
    }
    
    if (stop_pc != 0) {
        qemu_plugin_register_vcpu_tb_exec_cb(tb, check_stop,
                                             QEMU_PLUGIN_CB_NO_REGS,
                                             (void *)(uintptr_t)pc);
    }
    
    bb = g_hash_table_lookup(bb_table, &pc);
    
    if (!bb) {
        bb = g_new0(BasicBlock, 1);
        bb->pc = pc;
        bb->id = ++unique_bb_id;
        bb->n_insns = n_insns;
        bb->weighted_count = 0;
        bb->total_exec = 0;
        
        g_hash_table_insert(bb_table, &bb->pc, bb);
    }
    
    qemu_plugin_register_vcpu_tb_exec_cb(tb, track_interval_start,
                                         QEMU_PLUGIN_CB_NO_REGS, bb);
    
    qemu_plugin_register_vcpu_tb_exec_inline(tb, QEMU_PLUGIN_INLINE_ADD_U64,
                                             &bb->weighted_count, n_insns);
    
    qemu_plugin_register_vcpu_tb_exec_inline(tb, QEMU_PLUGIN_INLINE_ADD_U64,
                                             &bb->total_exec, 1);
    
    qemu_plugin_register_vcpu_tb_exec_inline(tb, QEMU_PLUGIN_INLINE_ADD_U64,
                                             &inst_count, n_insns);
    qemu_plugin_register_vcpu_tb_exec_inline(tb, QEMU_PLUGIN_INLINE_ADD_U64,
                                             &total_inst_count, n_insns);
    
    qemu_plugin_register_vcpu_tb_exec_cb(tb, check_interval,
                                         QEMU_PLUGIN_CB_NO_REGS, NULL);
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    if (plugin_active && tracking_enabled && inst_count > 0) {
        fprintf(stderr, "BBV: Discarding final partial interval (%"PRIu64" instructions)\n",
                inst_count);
    }
    
    fprintf(stderr, "BBV: Final stats:\n");
    fprintf(stderr, "BBV:   Total instructions: %"PRIu64"\n", total_inst_count);
    fprintf(stderr, "BBV:   Completed intervals: %"PRIu64"\n", completed_intervals);
    fprintf(stderr, "BBV:   Unique basic blocks: %u\n", g_hash_table_size(bb_table));
    
    if (bb_table) {
        g_hash_table_destroy(bb_table);
    }
    if (bbv_file) {
        gzclose(bbv_file);
    }
    if (simpoints_interval_file) {
        fclose(simpoints_interval_file);
    }
}

static void plugin_init(const char *name)
{
    char *bbv_name = g_strdup_printf("%s.bb.gz", name);
    char *interval_name = g_strdup_printf("%s.intervals.txt", name);
    
    bbv_file = gzopen(bbv_name, "w");
    simpoints_interval_file = fopen(interval_name, "w");
    
    if (!bbv_file || !simpoints_interval_file) {
        fprintf(stderr, "BBV: Failed to open output files\n");
        exit(1);
    }
    
    fprintf(simpoints_interval_file, "# SimPoint Start PC Information\n");
    fprintf(simpoints_interval_file, "# Format: Interval N: StartPC=0xXXXX Count=Y\n");
    fprintf(simpoints_interval_file, "# interval_size=%"PRIu64"\n", interval_size);
    fprintf(simpoints_interval_file, "# trigger_pc=0x%"PRIx64"\n", trigger_pc);
    fprintf(simpoints_interval_file, "# stop_pc=0x%"PRIx64"\n", stop_pc);
    fprintf(simpoints_interval_file, "#\n");
    
    g_free(bbv_name);
    g_free(interval_name);
    
    /* Use PC as key directly */
    bb_table = g_hash_table_new_full(g_int64_hash, g_int64_equal, NULL, g_free);
}

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    const char *bench_name = "trace";
    
    plugin_id = id;
    
    /* Parse arguments: name, trigger_pc, interval_size, stop_pc */
    if (argc > 0) {
        bench_name = argv[0];
    }
    
    if (argc > 1) {
        trigger_pc = strtoull(argv[1], NULL, 0);
        tracking_enabled = (trigger_pc == 0);
        if (trigger_pc != 0) {
            fprintf(stderr, "BBV: Will start at PC 0x%"PRIx64"\n", trigger_pc);
        }
    } else {
        tracking_enabled = true;
    }
    
    if (argc > 2) {
        interval_size = strtoull(argv[2], NULL, 0);
        if (interval_size == 0) {
            interval_size = DEFAULT_INTERVAL_SIZE;
        }
        fprintf(stderr, "BBV: Interval size: %"PRIu64"\n", interval_size);
    }
    
    if (argc > 3) {
        stop_pc = strtoull(argv[3], NULL, 0);
        if (stop_pc != 0) {
            fprintf(stderr, "BBV: Will stop at PC 0x%"PRIx64"\n", stop_pc);
        }
    }
    
    plugin_init(bench_name);
    qemu_plugin_register_vcpu_tb_trans_cb(id, tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    
    fprintf(stderr, "BBV: Plugin initialized\n");
    
    return 0;
}