/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2020 Alfredo Mazzinghi
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdint.h>

#include "qemu/osdep.h"
#include "qemu/range.h"
#include "qemu/log.h"
#include "cpu-param.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/log.h"
#include "exec/helper-proto.h"
#include "exec/log_instr.h"
#include "exec/memop.h"
#include "disas/disas.h"
#include "exec/translator.h"
#include "tcg/tcg.h"
#include "tcg/tcg-op.h"
#include "qapi/error.h"
#include "sysemu/runstate.h"
#include <zlib.h>

/*
 * CHERI common instruction logging.
 *
 * This is the central implementation of the CPU_LOG_INSTR tracing.
 * The same functions can be used by CHERI targets to append to the instruction
 * log buffer. Once the instruction is fully processed, the target commits the
 * log buffer and depending on the instruction operations and -dfilter options
 * we either flush the buffer or drop it.
 * A central desing goal is to reliably log multiple register updates and memory
 * accesses performed by an instruction. We also want to allow to log arbitary
 * events via special no-op instructions. Extra text debug output can also be
 * appended to the instruction log info.
 *
 * The output trace format can be easily changed by implementing a new set of
 * trace_fmt_hooks.
 *
 * The CPU_LOG_INSTR flag is used as a global enable to signal that logging is
 * active. Each CPU holds a private logging state, that can be controlled
 * individually.
 *
 * TODO(am2419): how do we deal with orderding in case multiple registers are updated?
 * This is critical to recognize which value goes in which register, and also how to
 * tie multiple memory accesses to the respective value/register.
 * We could add an explicit target-specific register ID handle in place of the
 * register name. This could be used also to fetch the register name and would
 * provide an identifier to external parsers.
 * Memory updates are harder to deal with, at least in the current format, perhaps
 * the semantic of the instruction is enough to recover the ordering from a trace.
 */

#ifdef CONFIG_TCG_LOG_INSTR

#define CONFIG_DEBUG_TCG

#ifdef CONFIG_DEBUG_TCG
#define log_assert(x) assert((x))
#else
#define log_assert(x)
#endif

#ifndef TARGET_MAX_INSN_SIZE
#error "Target does not define TARGET_MAX_INSN_SIZE in cpu-param.h"
#endif

/*
 * -dfilter ranges in common logging implementation.
 */
extern GArray *debug_regions;

extern GArray *simpoints;
extern GArray *adjusted_simpoints; //adjusted_simpoints = simpoints if we have no warmup

extern GArray *simpoint_pcs;   
static GHashTable *pc_exec_count_map = NULL;

extern uint64_t INTERVAL_SIZE;
extern uint64_t START_PC; 
extern bool SIMPOINT_PROCESS_FILTER;

static simpoint_state_t sp_state = {
    .current_idx = -1, .mode = SIMPOINT_MODE_INACTIVE
};
extern char *SIMPOINT_BBV_PATH;
extern char *SIMPOINT_BBV_KEY;


/*
 * Instruction log info associated with each committed log entry.
 * This is stored in the per-cpu log cpustate.
 */
typedef struct cpu_log_instr_info {
#define cpu_log_iinfo_startzero asid
    uint16_t asid;
    int flags;
/* Entry contains a synchronous exception */
#define LI_FLAG_INTR_TRAP 1
/* Entry contains an asynchronous exception */
#define LI_FLAG_INTR_ASYNC (1 << 1)
#define LI_FLAG_INTR_MASK 0x3
/* Entry contains a CPU mode-switch and associated code */
#define LI_FLAG_MODE_SWITCH (1 << 2)
#define NUM_INSTR_DESTINATIONS 2
#define NUM_INSTR_SOURCES 4
    qemu_log_instr_cpu_mode_t next_cpu_mode;
    uint32_t intr_code;
    target_ulong intr_vector;
    target_ulong intr_faultaddr;

    target_ulong pc;
    /* Generic instruction opcode buffer */
    int insn_size;

    /*ChampSim Trace*/
    uint8_t is_branch;
    uint8_t branch_taken;
    qemu_log_branch_type_t branch_type; 

    qemu_log_reg_info src_regs[NUM_INSTR_SOURCES];
    qemu_log_reg_info dst_regs[NUM_INSTR_DESTINATIONS];
    int num_src_regs;
    int num_dst_regs;

    char insn_bytes[TARGET_MAX_INSN_SIZE];
#ifdef TARGET_CHERI
    /* Authorizing capability for memory accesses */
    bool has_auth_cap;
    cap_register_t auth_cap;
    uint32_t auth_cap_regnum;  /* register number (or CHERI_EXC_REGNUM_DDC) */
#endif
#define cpu_log_iinfo_endzero mem
    /*
     * For now we allow multiple accesses to be tied to one instruction.
     * Some architectures may have multiple memory accesses
     * in the same instruction (e.g. x86-64 pop r/m64,
     * vector/matrix instructions, load/store pair). It is unclear
     * whether we would treat these as multiple trace "entities".
     *
     * Array of log_meminfo_t
     */
    GArray *mem;
    /* Register modifications. Array of log_reginfo_t */
    GArray *regs;
    /* Extra text-only log */
    GString *txt_buffer;
} cpu_log_instr_info_t;

/*
 * Register update info.
 * This records a CPU register update occurred during an instruction.
 */
typedef struct {
    uint16_t flags;
#define LRI_CAP_REG    1
#define LRI_HOLDS_CAP  2

    const char *name;
    union {
        target_ulong gpr;
#ifdef TARGET_CHERI
        cap_register_t cap;
#endif
    };
} log_reginfo_t;

#define reginfo_is_cap(ri) (ri->flags & LRI_CAP_REG)
#define reginfo_has_cap(ri) (reginfo_is_cap(ri) && (ri->flags & LRI_HOLDS_CAP))

/*
 * Memory access info.
 * This records a memory access occurred during an instruction.
 */
typedef struct {
    uint8_t flags;
#define LMI_LD 1
#define LMI_ST 2
#define LMI_CAP 4
    MemOp op;
    target_ulong addr;
    union {
        uint64_t value;
#ifdef TARGET_CHERI
        cap_register_t cap;
#endif
    };
} log_meminfo_t;

#define meminfo_is_cap(mi) (mi->flags & LMI_CAP)


/*
 * Callbacks defined by a trace format implementation.
 * These are called to covert instruction tracing events to the corresponding
 * binary or text format.
 */
struct trace_fmt_hooks {
    void (*emit_header)(CPUArchState *env);
    void (*emit_start)(CPUArchState *env, target_ulong pc);
    void (*emit_stop)(CPUArchState *env, target_ulong pc);
    void (*emit_entry)(CPUArchState *env, cpu_log_instr_info_t *iinfo);
};
typedef struct trace_fmt_hooks trace_fmt_hooks_t;

/* Global trace format selector. Defaults to text tracing */
qemu_log_instr_fmt_t qemu_log_instr_format = QLI_FMT_TEXT;

/* Current format callbacks. */
static trace_fmt_hooks_t *trace_format = NULL;

/* Existing format callbacks list, indexed by qemu_log_instr_fmt_t */
static trace_fmt_hooks_t trace_formats[];

/*
 * CHERI binary trace format, originally used for MIPS only.
 * The format is limited to one entry per instruction, each
 * entry can hold at most one register modification and one
 * memory address.
 * Note that the CHERI format is the legacy MIPS format and
 * assumes big-endian byte order.
 */
typedef struct {
    uint8_t entry_type;
#define CTE_NO_REG  0   /* No register is changed. */
#define CTE_GPR     1   /* GPR change (val2) */
#define CTE_LD_GPR  2   /* Load into GPR (val2) from address (val1) */
#define CTE_ST_GPR  3   /* Store from GPR (val2) to address (val1) */
#define CTE_CAP     11  /* Cap change (val2,val3,val4,val5) */
#define CTE_LD_CAP  12  /* Load Cap (val2,val3,val4,val5) from addr (val1) */
#define CTE_ST_CAP  13  /* Store Cap (val2,val3,val4,val5) to addr (val1) */
    // uint8_t exception;  /* 0=none, 1=TLB Mod, 2=TLB Load, 3=TLB Store, etc. */
#define CTE_EXCEPTION_NONE 31
    // uint16_t cycles;    /* Currently not used. */
    uint32_t inst;      /* Encoded instruction. */
    uint64_t pc;        /* PC value of instruction. */
    uint64_t val1;      /* val1 is used for memory address. */
    uint64_t val2;      /* val2, val3, val4, val5 are used for reg content. */
    uint64_t val3;
    uint64_t val4;
    uint64_t val5;
    // uint8_t thread;     /* Hardware thread/CPU (i.e. cpu->cpu_index ) */
    // uint8_t asid;       /* Address Space ID */
} __attribute__((packed)) cheri_trace_entry_t;


typedef struct {
#define REG_STACK_POINTER 6
#define REG_FLAGS  25
#define REG_INSTRUCTION_POINTER 26
#define REG_RETURN 1
#define NUM_INSTR_DESTINATIONS 2
#define NUM_INSTR_SOURCES 4
    // instruction pointer or PC (Program Counter)
  uint64_t ip;

  // branch info
  uint8_t is_branch;
  uint8_t branch_taken;

  uint8_t destination_registers[NUM_INSTR_DESTINATIONS]; // output registers
  uint8_t source_registers[NUM_INSTR_SOURCES];           // input registers

  uint64_t destination_memory[NUM_INSTR_DESTINATIONS]; // output memory
  uint64_t source_memory[NUM_INSTR_SOURCES];           // input memory
} champsim_trace_entry_t;


#define CAP_OP_NONE         0x00
#define CAP_OP_AUTH         0x01
#define CAP_OP_TRANSFERRED  0x02
#define CAP_OP_BOTH         (CAP_OP_AUTH | CAP_OP_TRANSFERRED)
#define CAP_OP_PRESIMPOINT  0x04

typedef struct {
#define REG_STACK_POINTER 6
#define REG_FLAGS  25
#define REG_INSTRUCTION_POINTER 26
#define REG_RETURN 1
#define NUM_INSTR_DESTINATIONS 2
#define NUM_INSTR_SOURCES 4
    // instruction pointer or PC (Program Counter)
    uint64_t ip;

    // branch info
    uint8_t is_branch;
    uint8_t branch_taken;

    uint8_t destination_registers[NUM_INSTR_DESTINATIONS]; // output registers
    uint8_t source_registers[NUM_INSTR_SOURCES];           // input registers

    uint64_t destination_memory[NUM_INSTR_DESTINATIONS]; // output memory
    uint64_t source_memory[NUM_INSTR_SOURCES];           // input memory

    uint64_t auth_base;
    uint64_t auth_length;
    uint64_t auth_offset;
    uint32_t auth_perms;
    uint8_t  auth_tag;
 
    /* Transferred capability (cap load/store value) */
    uint64_t cap_base;
    uint64_t cap_length;
    uint64_t cap_offset;
    uint32_t cap_perms;
    uint8_t  cap_tag;
 
    /* What's present */
    uint8_t  cap_op;
} champsim_cheri_trace_entry_t;


/* Version 3 Cheri Stream Trace header info */
#define CTE_QEMU_VERSION    (0x80U + 3)
#define CTE_QEMU_MAGIC      "CheriTraceV03"

/* Number of per-cpu ring buffer entries for ring-buffer tracing mode */
#define MIN_ENTRY_BUFFER_SIZE (1 << 16)

static unsigned long reset_entry_buffer_size = MIN_ENTRY_BUFFER_SIZE;

/*
 * Fetch the log state for a cpu.
 */
static inline cpu_log_instr_state_t *get_cpu_log_state(CPUArchState *env)
{
    return &env_cpu(env)->log_state;
}

/*
 * Fetch the given cpu current instruction info
 */
static inline cpu_log_instr_info_t *get_cpu_log_instr_info(CPUArchState *env)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);

    return &g_array_index(cpulog->instr_info, cpu_log_instr_info_t,
        cpulog->ring_head);
}

/* Text trace format emitters */


/*
 * Emit textual trace representation of memory access
 */

static inline void emit_text_ldst(log_meminfo_t *minfo, const char *direction)
{

#ifndef TARGET_CHERI
    log_assert((minfo->flags & LMI_CAP) == 0 &&
               "Capability memory access without CHERI support");
#else
    if (minfo->flags & LMI_CAP) {
        qemu_log("    Cap Memory %s [" TARGET_FMT_lx "] = v:%d PESBT:"
                 TARGET_FMT_lx " Cursor:" TARGET_FMT_lx "\n",
                 direction, minfo->addr, minfo->cap.cr_tag,
                 CAP_cc(compress_mem)(&minfo->cap),
                 cap_get_cursor(&minfo->cap));        
    } else
#endif
    {
        switch (memop_size(minfo->op)) {
        default:
            qemu_log("    Unknown memory access width\n");
            /* fallthrough */
        case 8:
            qemu_log("    Memory %s [" TARGET_FMT_lx "] = " TARGET_FMT_plx "\n",
                     direction, minfo->addr, minfo->value);
            break;
        case 4:
            qemu_log("    Memory %s [" TARGET_FMT_lx "] = %08x\n",
                     direction, minfo->addr, (uint32_t)minfo->value);
            break;
        case 2:
            qemu_log("    Memory %s [" TARGET_FMT_lx "] = %04x\n",
                     direction, minfo->addr, (uint16_t)minfo->value);
            break;
        case 1:
            qemu_log("    Memory %s [" TARGET_FMT_lx "] = %02x\n",
                     direction, minfo->addr, (uint8_t)minfo->value);
            break;
        }
    }
}

/*
 * Emit textual trace representation of register modification
 */
static inline void emit_text_reg(log_reginfo_t *rinfo)
{
#ifndef TARGET_CHERI
    log_assert(!reginfo_is_cap(rinfo) && "Register marked as capability "
               "register whitout CHERI support");
#else
    if (reginfo_is_cap(rinfo)) {
        if (reginfo_has_cap(rinfo))
            qemu_log("    Write %s|" PRINT_CAP_FMTSTR_L1 ""
                     " |" PRINT_CAP_FMTSTR_L2 "\n",
                     rinfo->name,
                     PRINT_CAP_ARGS_L1(&rinfo->cap),
                     PRINT_CAP_ARGS_L2(&rinfo->cap));
        else
            qemu_log("  %s <- " TARGET_FMT_lx " (setting integer value)\n",
                     rinfo->name, rinfo->gpr);
    } else
#endif
    {
        qemu_log("    Write %s = " TARGET_FMT_lx "\n", rinfo->name,
                 rinfo->gpr);
    }
}


/*
 * Emit textual trace entry to the log.
 */
static void emit_text_entry(CPUArchState *env, cpu_log_instr_info_t *iinfo)
{
    QemuLogFile *logfile;
    int i;


    /* Dump CPU-ID:ASID + address */
    qemu_log("[%d:%d] ", env_cpu(env)->cpu_index, iinfo->asid);

    /*
     * Instruction disassembly, note that we use the instruction info
     * opcode bytes, without accessing target memory here.
     */
    rcu_read_lock();
    logfile = qatomic_rcu_read(&qemu_logfile);
    if (logfile) {
        target_disas_buf(logfile->fd, env_cpu(env), iinfo->insn_bytes,
                         sizeof(iinfo->insn_bytes), iinfo->pc, 1);
    }
    rcu_read_unlock();


    /*
     * TODO(am2419): what to do with injected instructions?
     * Is the rvfi_dii_trace state valid at log commit?
     */

    /* Dump mode switching info */
    if (iinfo->flags & LI_FLAG_MODE_SWITCH)
        qemu_log("-> Switch to %s mode\n", cpu_get_mode_name(iinfo->next_cpu_mode));
    /* Dump interrupt/exception info */
    switch (iinfo->flags & LI_FLAG_INTR_MASK) {
    case LI_FLAG_INTR_TRAP:
        qemu_log("-> Exception #%u vector 0x" TARGET_FMT_lx
                 " fault-addr 0x" TARGET_FMT_lx "\n",
                 iinfo->intr_code, iinfo->intr_vector, iinfo->intr_faultaddr);
        break;
    case LI_FLAG_INTR_ASYNC:
        qemu_log("-> Interrupt #%04x vector 0x" TARGET_FMT_lx "\n",
                 iinfo->intr_code, iinfo->intr_vector);
        break;
    default:
        /* No interrupt */
        break;
    }

    /* Dump memory access */
    for (i = 0; i < iinfo->mem->len; i++) {
        log_meminfo_t *minfo = &g_array_index(iinfo->mem, log_meminfo_t, i);

        if (minfo->flags & LMI_LD) {

            emit_text_ldst(minfo, "Read");
        } else if (minfo->flags & LMI_ST) {
            emit_text_ldst(minfo, "Write");
        }
    }

    /* Dump register changes and side-effects */
    for (i = 0; i < iinfo->regs->len; i++) {
        log_reginfo_t *rinfo = &g_array_index(iinfo->regs, log_reginfo_t, i);
        emit_text_reg(rinfo);
    }

#ifdef TARGET_CHERI
    if (iinfo->has_auth_cap) {
        const cap_register_t *ac = &iinfo->auth_cap;
        qemu_log("    Auth Cap [%s%u] v:%d PESBT:" TARGET_FMT_lx
                 " Cursor:" TARGET_FMT_lx "\n",
                 iinfo->auth_cap_regnum == CHERI_EXC_REGNUM_DDC ? "DDC" : "c",
                 iinfo->auth_cap_regnum,
                 ac->cr_tag,
                 CAP_cc(compress_mem)(ac),
                 cap_get_cursor(ac));
    }
#endif
    /* Dump extra logged messages, if any */
    if (iinfo->txt_buffer->len > 0)
        qemu_log("%s", iinfo->txt_buffer->str);

}

/*
 * Emit text tracing start event.
 */
static void emit_text_start(CPUArchState *env, target_ulong pc)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);

    if (cpulog->loglevel == QEMU_LOG_INSTR_LOGLEVEL_USER) {
        qemu_log("[%u:%u] Requested user-mode only instruction logging "
                 "@ " TARGET_FMT_lx " \n",
                 env_cpu(env)->cpu_index, cpu_get_asid(env, pc), pc);
    } else {
        qemu_log("[%u:%u] Requested instruction logging @ " TARGET_FMT_lx " \n",
                 env_cpu(env)->cpu_index, cpu_get_asid(env, pc), pc);
    }
}

/*
 * Emit text tracing stop event.
 */
static void emit_text_stop(CPUArchState *env, target_ulong pc)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);

    if (cpulog->loglevel == QEMU_LOG_INSTR_LOGLEVEL_USER) {
        qemu_log("[%u:%u] Disabled user-mode only instruction logging "
                 "@ " TARGET_FMT_lx " \n",
                 env_cpu(env)->cpu_index, cpu_get_asid(env, pc), pc);
    } else {
        qemu_log("[%u:%u] Disabled instruction logging @ " TARGET_FMT_lx " \n",
                 env_cpu(env)->cpu_index, cpu_get_asid(env, pc), pc);
    }
}

/* CHERI trace V3 format emitters */

/*
 * Emit cvtrace trace trace header. This is a magic byte + string
 */
static void emit_cvtrace_header(CPUArchState *env)
{
    FILE *logfile = qemu_log_lock();
    char buffer[sizeof(cheri_trace_entry_t)];

    buffer[0] = CTE_QEMU_VERSION;
    g_strlcpy(buffer + 1, CTE_QEMU_MAGIC, sizeof(buffer) - 2);
    fwrite(buffer, sizeof(buffer), 1, logfile);
    qemu_log_unlock(logfile);
}

/*
 * Emit cvtrace trace entry.
 * Note: this format is very MIPS-specific.
 */
static void emit_cvtrace_entry(CPUArchState *env, cpu_log_instr_info_t *iinfo)
{
    FILE *logfile;
    cheri_trace_entry_t entry;
    //static uint16_t cycles = 0; // TODO(am2419): this should be a per-cpu counter.
    uint32_t *insn = (uint32_t *)&iinfo->insn_bytes[0];

    entry.entry_type = CTE_NO_REG;
    //entry.thread = (uint8_t)env_cpu(env)->cpu_index;
    //entry.asid = (uint8_t)iinfo->asid;
    entry.pc = cpu_to_be64(iinfo->pc);
    //entry.cycles = cpu_to_be16(cycles++);
    entry.inst = cpu_to_be32(*insn);

    /*
     * TODO(am2419): The instruction bytes are alread in target byte-order, however
     * cheritrace does not currently expect this.
     */
    // switch (iinfo->flags & LI_FLAG_INTR_MASK) {
    // case LI_FLAG_INTR_TRAP:
    //     entry.exception = (uint8_t)(iinfo->intr_code & 0xff);
    // case LI_FLAG_INTR_ASYNC:
    //     entry.exception = 0;
    // default:
    //     entry.exception = CTE_EXCEPTION_NONE;
    // }

    if (iinfo->regs->len) {
        log_reginfo_t *rinfo = &g_array_index(iinfo->regs, log_reginfo_t, 0);
#ifndef TARGET_CHERI
        log_assert(!reginfo_is_cap(rinfo) && "Capability register access "
                   "without CHERI support");
#else
        if (reginfo_is_cap(rinfo)) {
            cap_register_t intcap;
            cap_register_t *cr = &rinfo->cap;

            if (!reginfo_has_cap(rinfo)) {
                // cvtrace expects a null capability in the integer case
                cr = null_capability(&intcap);
            }

            uint64_t metadata = (((uint64_t)cr->cr_tag << 63) |
                                 ((uint64_t)cap_get_otype_signext(cr) << 32) |
                                 ((uint64_t)COMBINED_PERMS_VALUE(cr) << 1) |
                                 (uint64_t)(cap_is_unsealed(cr) ? 0 : 1));

            entry.entry_type = CTE_CAP;
            entry.val2 = cpu_to_be64(metadata);
            entry.val3 = cpu_to_be64(cap_get_cursor(cr));
            entry.val4 = cpu_to_be64(cap_get_base(cr));
            entry.val5 = cpu_to_be64(cap_get_length_sat(cr));
        } else
#endif
        {
            entry.entry_type = CTE_GPR;
            entry.val2 = cpu_to_be64(rinfo->gpr);
        }
    }

    if (iinfo->mem->len) {
        log_meminfo_t *minfo = &g_array_index(iinfo->mem, log_meminfo_t, 0);
#ifndef TARGET_CHERI
        log_assert(!meminfo_is_cap(minfo) && "Capability memory access "
                   "without CHERI support");
#else        
        if (meminfo_is_cap(minfo)) {     
      
            if (minfo->flags & LMI_LD) {
                entry.entry_type = CTE_LD_CAP;
            } else if (minfo->flags & LMI_ST) {
                entry.entry_type = CTE_ST_CAP;
            }
        } else
#endif
        {
            if (minfo->flags & LMI_LD) {
                entry.entry_type = CTE_LD_GPR;
            } else if (minfo->flags & LMI_ST) {
                entry.entry_type = CTE_ST_GPR;   
            }
        }
        entry.val1 = cpu_to_be64(minfo->addr);
    }

    logfile = qemu_log_lock();
    fwrite(&entry, sizeof(entry), 1, logfile);
    qemu_log_unlock(logfile);
}



static void emit_cvtrace_start(CPUArchState *env, target_ulong pc)
{
    // TODO(am2419) Emit an event for instruction logging start
}

static void emit_cvtrace_stop(CPUArchState *env, target_ulong pc)
{
    // TODO(am2419) Emit an event for instruction logging stop
}

static uint8_t remap_regid(uint8_t reg, LogRegType type)
{
    const uint8_t CHAMPSIM_FP_REG_BASE = 32;
    const uint8_t TRANSLATED_REG_IP    = 66;
    const uint8_t TRANSLATED_REG_SP    = 67;
    const uint8_t TRANSLATED_REG_FLAGS = 68;

    switch (type) {
        case LOG_REG_TYPE_GPR:
        case LOG_REG_TYPE_CAP:
            switch (reg) {
            case 2: return REG_STACK_POINTER;  // x2/sp
            case REG_STACK_POINTER: return TRANSLATED_REG_SP;
            case REG_FLAGS: return TRANSLATED_REG_FLAGS;
            case REG_INSTRUCTION_POINTER: return TRANSLATED_REG_IP;
            default: return reg;
            }

        case LOG_REG_TYPE_FPR:
            return reg + CHAMPSIM_FP_REG_BASE;

        case LOG_REG_TYPE_NONE:
        default: 
            return reg;
    }
}

static void emit_champsim_entry(CPUArchState *env, cpu_log_instr_info_t *iinfo)
{
    FILE *logfile;
    champsim_trace_entry_t trace = {0};
    trace.ip = iinfo->pc;
    trace.is_branch = iinfo->is_branch;
    trace.branch_taken = iinfo->branch_taken;

    uint32_t source_mem_idx = 0;
    uint32_t dest_mem_idx = 0;
    const uint64_t CACHE_LINE_SIZE = 64;
    const uint64_t CACHE_LINE_MASK = CACHE_LINE_SIZE - 1;

    for (int i = 0; i < iinfo->mem->len; i++) {
        log_meminfo_t *minfo = &g_array_index(iinfo->mem, log_meminfo_t, i);
        uint64_t address = minfo->addr;
        uint8_t access_size = memop_size(minfo->op);
        uint64_t cl_start = address & ~CACHE_LINE_MASK;
        uint64_t cl_end = (address + access_size - 1) & ~CACHE_LINE_MASK;
        bool spans = (cl_start != cl_end);

        if (minfo->flags & LMI_LD) {
            if (source_mem_idx < NUM_INSTR_SOURCES)
                trace.source_memory[source_mem_idx++] = address;
            if (spans && source_mem_idx < NUM_INSTR_SOURCES)
                trace.source_memory[source_mem_idx++] = cl_end;
        } else if (minfo->flags & LMI_ST) {
            if (dest_mem_idx < NUM_INSTR_DESTINATIONS)
                trace.destination_memory[dest_mem_idx++] = address;
            if (spans && dest_mem_idx < NUM_INSTR_DESTINATIONS)
                trace.destination_memory[dest_mem_idx++] = cl_end;
        }
    }
    
    if (iinfo->is_branch) {
        switch (iinfo->branch_type) {
            case BRANCH_DIRECT_JUMP: // writes IP only
                trace.destination_registers[0] = REG_INSTRUCTION_POINTER;
                break;

            case BRANCH_INDIRECT: // writes IP and reads other
                trace.destination_registers[0] = REG_INSTRUCTION_POINTER;
                trace.source_registers[0]      = remap_regid(iinfo->src_regs[0].reg_id, LOG_REG_TYPE_GPR);
                break;

            case BRANCH_CONDITIONAL: // writes IP, reads IP and reads other
                trace.destination_registers[0] = REG_INSTRUCTION_POINTER;
                trace.source_registers[0]      = REG_INSTRUCTION_POINTER;
                trace.source_registers[1]      = remap_regid(iinfo->src_regs[0].reg_id, LOG_REG_TYPE_GPR);
                trace.source_registers[2]      = remap_regid(iinfo->src_regs[1].reg_id, LOG_REG_TYPE_GPR);
                /*
                 * REG_FLAGS marks this as a conditional branch even when it
                 * compares ra or sp (which would otherwise look like a return
                 * or a stack op). Nothing writes REG_FLAGS (x25 is remapped),
                 * so it adds no dependency.
                 */
                trace.source_registers[3]      = REG_FLAGS;
                break;

            case BRANCH_DIRECT_CALL: 
                trace.destination_registers[0] = REG_INSTRUCTION_POINTER;
                trace.destination_registers[1] = remap_regid(iinfo->dst_regs[0].reg_id, LOG_REG_TYPE_GPR);
                trace.source_registers[0]      = REG_INSTRUCTION_POINTER;
                break;
            
            case BRANCH_INDIRECT_CALL: 
                trace.destination_registers[0] = REG_INSTRUCTION_POINTER;
                trace.destination_registers[1] = remap_regid(iinfo->dst_regs[0].reg_id, LOG_REG_TYPE_GPR);
                trace.source_registers[0]      = REG_INSTRUCTION_POINTER;
                trace.source_registers[1]      = remap_regid(iinfo->src_regs[0].reg_id, LOG_REG_TYPE_GPR);
                break;

            case BRANCH_RETURN: // reads other, writes SP, writes IP, reads SP
                trace.destination_registers[0] = REG_INSTRUCTION_POINTER;
                trace.source_registers[0]      = REG_RETURN;
                trace.source_registers[1]      = REG_INSTRUCTION_POINTER; 
                break;

            case BRANCH_CJAL:   /* capability-mode direct call */
                trace.destination_registers[0] = REG_INSTRUCTION_POINTER;
                trace.destination_registers[1] = remap_regid(iinfo->dst_regs[0].reg_id, LOG_REG_TYPE_CAP);
                trace.source_registers[0]      = REG_INSTRUCTION_POINTER;
                break;

            case BRANCH_CJALR:  /* capability indirect call */
                trace.destination_registers[0] = REG_INSTRUCTION_POINTER;
                trace.destination_registers[1] = remap_regid(iinfo->dst_regs[0].reg_id, LOG_REG_TYPE_CAP);
                trace.source_registers[0]      = REG_INSTRUCTION_POINTER;
                trace.source_registers[1]      = remap_regid(iinfo->src_regs[0].reg_id, LOG_REG_TYPE_CAP);
                break;

            case BRANCH_OTHER:
                break;

            case NOT_BRANCH:
            default:
            fprintf(stderr, 
                "FATAL: Unrecognized branch type %d at PC 0x%" PRIx64 
                " (is_branch=%d, mode=%d)\n",
                iinfo->branch_type, (uint64_t)iinfo->pc, 
                iinfo->is_branch, sp_state.mode);
                assert(false && "Error: Unrecognized branch type\n");
        }
    } else {
        uint8_t num_src = MIN(iinfo->num_src_regs, NUM_INSTR_SOURCES);
        for (int i = 0; i < num_src; i++) 
            trace.source_registers[i] = remap_regid(iinfo->src_regs[i].reg_id, iinfo->src_regs[i].type);
        
        uint8_t num_dst = MIN(iinfo->num_dst_regs, NUM_INSTR_DESTINATIONS);
        for (int i = 0; i < num_dst; i++) 
            trace.destination_registers[i] = remap_regid(iinfo->dst_regs[i].reg_id, iinfo->dst_regs[i].type); 
    }

    logfile = qemu_log_lock();
    fwrite(&trace, sizeof(trace), 1, logfile);
    qemu_log_unlock(logfile);
}

static void emit_champsim_start(CPUArchState *env, target_ulong pc)
{
    // TODO(am2419) Emit an event for instruction logging start
}

static void emit_champsim_stop(CPUArchState *env, target_ulong pc)
{
    // TODO(am2419) Emit an event for instruction logging stop
}

static void emit_champsim_cheri_entry(CPUArchState *env, cpu_log_instr_info_t *iinfo)
{
    FILE *logfile;
    champsim_cheri_trace_entry_t trace = {0};
    trace.ip = iinfo->pc;
    trace.is_branch = iinfo->is_branch;
    trace.branch_taken = iinfo->branch_taken;
    trace.cap_op = CAP_OP_NONE;

#ifdef TARGET_CHERI
    /* Auth cap: set by cap_check_common / ddc_check_bounds */
    if (iinfo->has_auth_cap) {
        const cap_register_t *ac = &iinfo->auth_cap;
        trace.auth_tag    = ac->cr_tag;
        trace.auth_base   = cap_get_base(ac);
        trace.auth_length = cap_get_length_sat(ac);
        trace.auth_offset = cap_get_offset(ac);
        trace.auth_perms  = cap_get_perms(ac);
        trace.cap_op     |= CAP_OP_AUTH;
        // qemu_log("  AUTH_CAP: TAG=%u BASE=%016" PRIx64 " LEN=%016" PRIx64 " OFF=%016" PRIx64 " PERMS=0x%08x\n",
        // trace.auth_tag, trace.auth_base, trace.auth_length, trace.auth_offset, trace.auth_perms);
    }
 
    /* Transferred cap: capability value loaded/stored through memory */
    for (int i = 0; i < iinfo->mem->len; i++) {
        log_meminfo_t *minfo = &g_array_index(iinfo->mem, log_meminfo_t, i);
        if (meminfo_is_cap(minfo) && minfo->cap.cr_tag) {
            cap_register_t *cr = &minfo->cap;
            trace.cap_tag    = cr->cr_tag;
            trace.cap_base   = cap_get_base(cr);
            trace.cap_length = cap_get_length_sat(cr);
            trace.cap_offset = cap_get_offset(cr);
            trace.cap_perms  = cap_get_perms(cr);
            trace.cap_op    |= CAP_OP_TRANSFERRED;
            // qemu_log("  XFER_CAP: TAG=%u BASE=%016" PRIx64 " LEN=%016" PRIx64 " OFF=%016" PRIx64 " PERMS=0x%08x\n",
            // trace.cap_tag, trace.cap_base, trace.cap_length, trace.cap_offset, trace.cap_perms);
            break;
            
        }
    }
#endif

    uint32_t source_mem_idx = 0;
    uint32_t dest_mem_idx = 0;
    const uint64_t CACHE_LINE_SIZE = 64;
    const uint64_t CACHE_LINE_MASK = CACHE_LINE_SIZE - 1;

    for (int i = 0; i < iinfo->mem->len; i++) {
        log_meminfo_t *minfo = &g_array_index(iinfo->mem, log_meminfo_t, i);
        uint64_t address = minfo->addr;
        uint8_t access_size = memop_size(minfo->op);
        uint64_t cl_start = address & ~CACHE_LINE_MASK;
        uint64_t cl_end = (address + access_size - 1) & ~CACHE_LINE_MASK;
        bool spans = (cl_start != cl_end);


        if (minfo->flags & LMI_LD) {
            if (source_mem_idx < NUM_INSTR_SOURCES)
                trace.source_memory[source_mem_idx++] = address;
            if (spans && source_mem_idx < NUM_INSTR_SOURCES)
                trace.source_memory[source_mem_idx++] = cl_end;
        } else if (minfo->flags & LMI_ST) {
            if (dest_mem_idx < NUM_INSTR_DESTINATIONS)
                trace.destination_memory[dest_mem_idx++] = address;
            if (spans && dest_mem_idx < NUM_INSTR_DESTINATIONS)
                trace.destination_memory[dest_mem_idx++] = cl_end;
        }
    }

    if (iinfo->is_branch) {
        switch (iinfo->branch_type) {
            case BRANCH_DIRECT_JUMP:
                trace.destination_registers[0] = REG_INSTRUCTION_POINTER;
                break;
            case BRANCH_INDIRECT:
                trace.destination_registers[0] = REG_INSTRUCTION_POINTER;
                trace.source_registers[0]      = remap_regid(iinfo->src_regs[0].reg_id, LOG_REG_TYPE_GPR);
                break;
            case BRANCH_CONDITIONAL:
                trace.destination_registers[0] = REG_INSTRUCTION_POINTER;
                trace.source_registers[0]      = REG_INSTRUCTION_POINTER;
                trace.source_registers[1]      = remap_regid(iinfo->src_regs[0].reg_id, LOG_REG_TYPE_GPR);
                trace.source_registers[2]      = remap_regid(iinfo->src_regs[1].reg_id, LOG_REG_TYPE_GPR);
                /*
                 * REG_FLAGS marks this as a conditional branch even when it
                 * compares ra or sp (which would otherwise look like a return
                 * or a stack op). Nothing writes REG_FLAGS (x25 is remapped),
                 * so it adds no dependency.
                 */
                trace.source_registers[3]      = REG_FLAGS;
                break;
            case BRANCH_DIRECT_CALL:
                trace.destination_registers[0] = REG_INSTRUCTION_POINTER;
                trace.destination_registers[1] = remap_regid(iinfo->dst_regs[0].reg_id, LOG_REG_TYPE_GPR);
                trace.source_registers[0]      = REG_INSTRUCTION_POINTER;
                break;
            case BRANCH_INDIRECT_CALL:
                trace.destination_registers[0] = REG_INSTRUCTION_POINTER;
                trace.destination_registers[1] = remap_regid(iinfo->dst_regs[0].reg_id, LOG_REG_TYPE_GPR);
                trace.source_registers[0]      = REG_INSTRUCTION_POINTER;
                trace.source_registers[1]      = remap_regid(iinfo->src_regs[0].reg_id, LOG_REG_TYPE_GPR);
                break;
            case BRANCH_RETURN:
                trace.destination_registers[0] = REG_INSTRUCTION_POINTER;
                trace.source_registers[0]      = REG_RETURN;
                trace.source_registers[1]      = REG_INSTRUCTION_POINTER;
                break;
            case BRANCH_CJAL:
                trace.destination_registers[0] = REG_INSTRUCTION_POINTER;
                trace.destination_registers[1] = remap_regid(iinfo->dst_regs[0].reg_id, LOG_REG_TYPE_CAP);
                trace.source_registers[0]      = REG_INSTRUCTION_POINTER;
                break;
            case BRANCH_CJALR:
                trace.destination_registers[0] = REG_INSTRUCTION_POINTER;
                trace.destination_registers[1] = remap_regid(iinfo->dst_regs[0].reg_id, LOG_REG_TYPE_CAP);
                trace.source_registers[0]      = REG_INSTRUCTION_POINTER;
                trace.source_registers[1]      = remap_regid(iinfo->src_regs[0].reg_id, LOG_REG_TYPE_CAP);
                break;
            default:
                assert(false && "Error: Unrecognized branch type\n");
        }
    } else {
        uint8_t num_src = MIN(iinfo->num_src_regs, NUM_INSTR_SOURCES);
        for (int i = 0; i < num_src; i++)
            trace.source_registers[i] = remap_regid(iinfo->src_regs[i].reg_id, iinfo->src_regs[i].type);

        uint8_t num_dst = MIN(iinfo->num_dst_regs, NUM_INSTR_DESTINATIONS);
        for (int i = 0; i < num_dst; i++)
            trace.destination_registers[i] = remap_regid(iinfo->dst_regs[i].reg_id, iinfo->dst_regs[i].type);
    }

    logfile = qemu_log_lock();
    fwrite(&trace, sizeof(trace), 1, logfile);
    qemu_log_unlock(logfile);
}

static void emit_champsim_cheri_start(CPUArchState *env, target_ulong pc)
{
    // TODO(am2419) Emit an event for instruction logging start
}

static void emit_champsim_cheri_stop(CPUArchState *env, target_ulong pc)
{
    // TODO(am2419) Emit an event for instruction logging stop
}

#ifdef TARGET_CHERI
#include "cheri_tagmem.h"

/*
 * Pre-SimPoint capability snapshot.
 *
 * A trace starts in the middle of the program, so the simulator's tag
 * memory starts empty. At the start of each SimPoint trace we write one
 * CAP_OP_PRESIMPOINT entry for every tagged capability currently in the
 * running process's user memory, read straight from QEMU's tag memory:
 * walk the user page table, and for each mapped page with tags, decode the
 * tagged granules. Being a snapshot of the real state, this includes
 * capabilities the kernel wrote into user memory (argv/auxv, signal frames,
 * ...) and nothing left behind by other processes or freed pages.
 * Each mapping is reported at its own VA, so a physical page mapped twice
 * appears under both addresses.
 */
#ifdef TARGET_RISCV64
typedef struct {
    CPUState *cs;
    FILE *logfile;
    uint64_t pages;
    uint64_t tagged_pages;
    uint64_t caps;
} cap_snapshot_state_t;

static void cap_snapshot_page(void *opaque, target_ulong va, hwaddr pa)
{
    cap_snapshot_state_t *st = opaque;
    unsigned long tags[BITS_TO_LONGS(TARGET_PAGE_SIZE / CHERI_CAP_SIZE)];
    uint8_t *host;

    st->pages++;
    if (!cheri_tag_read_phys_page(st->cs, pa, tags, &host))
        return;
    st->tagged_pages++;

    for (int i = 0; i < TARGET_PAGE_SIZE / CHERI_CAP_SIZE; i++) {
        if (!test_bit(i, tags))
            continue;

        const uint8_t *granule = host + i * CHERI_CAP_SIZE;
        target_ulong pesbt = ldq_p(granule + CHERI_MEM_OFFSET_METADATA) ^
                             CAP_NULL_XOR_MASK;
        target_ulong cursor = ldq_p(granule + CHERI_MEM_OFFSET_CURSOR);
        cap_register_t cr;
        CAP_cc(decompress_raw)(pesbt, cursor, true, &cr);

        champsim_cheri_trace_entry_t trace = {0};
        trace.destination_memory[0] = va + i * CHERI_CAP_SIZE;
        trace.cap_tag               = 1;
        trace.cap_base              = cap_get_base(&cr);
        trace.cap_length            = cap_get_length_sat(&cr);
        trace.cap_offset            = cap_get_offset(&cr);
        trace.cap_perms             = cap_get_perms(&cr);
        trace.cap_op                = CAP_OP_PRESIMPOINT;
        fwrite(&trace, sizeof(trace), 1, st->logfile);
        st->caps++;
    }
}
#endif /* TARGET_RISCV64 */

static void write_cap_snapshot_header(CPUArchState *env)
{
#ifdef TARGET_RISCV64
    cap_snapshot_state_t st = { .cs = env_cpu(env) };
    bool walked;

    st.logfile = qemu_log_lock();
    WITH_RCU_READ_LOCK_GUARD() {
        walked = riscv_cpu_for_each_user_page(env, cap_snapshot_page, &st);
    }
    qemu_log_unlock(st.logfile);

    if (!walked) {
        /*
         * User code under CheriBSD always runs with Sv39/Sv48 paging. A
         * trace without its capability header would look like "no tagged
         * memory" to the simulator, so stop rather than write one.
         */
        qemu_log_flush();
        fprintf(stderr, "FATAL: pre-SimPoint capability snapshot: user page "
                "table not walkable (satp mode %u; only Sv39/Sv48 are "
                "supported). Stopping instead of writing a trace without "
                "its capability header.\n",
                (unsigned)get_field(env->satp, SATP64_MODE));
        exit(1);
    }

    fprintf(stderr, "Pre-SimPoint capability snapshot: %" PRIu64
            " capabilities in %" PRIu64 " of %" PRIu64 " user pages\n",
            st.caps, st.tagged_pages, st.pages);
#else
    fprintf(stderr, "Pre-SimPoint capability snapshot not implemented "
            "for this target\n");
#endif
}
#endif


/* Core instruction logging implementation */

static inline void emit_start_event(CPUArchState *env, target_ulong pc)
{
    if ((get_cpu_log_state(env)->flags & QEMU_LOG_INSTR_FLAG_BUFFERED) == 0)
        trace_format->emit_start(env, pc);
}

static inline void emit_stop_event(CPUArchState *env, target_ulong pc)
{
    if ((get_cpu_log_state(env)->flags & QEMU_LOG_INSTR_FLAG_BUFFERED) == 0)
        trace_format->emit_stop(env, pc);
}

static inline void emit_entry_event(CPUArchState *env, cpu_log_instr_info_t *iinfo)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);

    if (cpulog->flags & QEMU_LOG_INSTR_FLAG_BUFFERED) {
        cpulog->ring_head = (cpulog->ring_head + 1) % cpulog->instr_info->len;
        if (cpulog->ring_tail == cpulog->ring_head)
            cpulog->ring_tail = (cpulog->ring_tail + 1) % cpulog->instr_info->len;
    }
    else {
        trace_format->emit_entry(env, iinfo);
    }
}

/* Reset instruction info buffer for next instruction */
static void reset_log_buffer(cpu_log_instr_state_t *cpulog,
                             cpu_log_instr_info_t *iinfo)
{
    memset(&iinfo->cpu_log_iinfo_startzero, 0,
           ((char *)&iinfo->cpu_log_iinfo_endzero -
            (char *)&iinfo->cpu_log_iinfo_startzero));
    g_array_remove_range(iinfo->regs, 0, iinfo->regs->len);
    g_array_remove_range(iinfo->mem, 0, iinfo->mem->len);
    g_string_erase(iinfo->txt_buffer, 0, -1);
    cpulog->force_drop = false;
    cpulog->starting = false;
}

static void global_loglevel_enable(void);

static void simpoint_open_trace(CPUArchState *env, int idx, bool is_warmup)
{
    char filename[256];

    if (sp_state.file_open)
        qemu_log_close();

    snprintf(filename, sizeof(filename), "simpoint_%d.trace", idx);
    /*
     * Not qemu_set_log_filename(): that re-runs the global instruction
     * log-level switch, which puts all CPUs in log level ALL. Windows
     * entered by switching from an adjacent one (no later USER switch)
     * were then traced with kernel-mode logging on: faulting user
     * instructions logged as completed, with the trap handler's register
     * writes attached. CPU_LOG_INSTR is set first so the file opens.
     */
    global_loglevel_enable();
    qemu_log_switch_file(filename, &error_fatal);
    sp_state.file_open = true;

#ifdef TARGET_CHERI
    if (trace_format == &trace_formats[4]) {
        write_cap_snapshot_header(env);
        fprintf(stderr, "Starting SimPoint %d (Warmup: %s), output: %s\n",
                idx, is_warmup ? "yes" : "no", filename);
    } else
#endif
    {
        fprintf(stderr, "Starting SimPoint %d (Warmup: %s), output: %s\n",
                idx, is_warmup ? "yes" : "no", filename);
    }
}

static void simpoint_close_trace(void)
{
    if (sp_state.file_open) {
        qemu_log_close();
        sp_state.file_open = false;
    }
} 

static void simpoint_end(CPUArchState *env, int last_idx)
{
    fprintf(stderr, "Ending SimPoint %d\n", sp_state.current_idx);
 
    simpoint_close_trace();
 
    sp_state.in_warmup = false;
 
    if (sp_state.current_idx == last_idx)
        sp_state.stop = true;
 
    sp_state.current_idx = -1;
}

static interval_match_t find_active_interval(uint64_t instr_count)
{
    interval_match_t m = { .should_trace = false, .is_warmup = false, .idx = -1 };

    for (int i = 0; i < simpoints->len; i++) {
        uint64_t adj_start = g_array_index(adjusted_simpoints, uint64_t, i);
        uint64_t start     = g_array_index(simpoints, uint64_t, i);
        uint64_t end       = start + INTERVAL_SIZE - 1;

        if (instr_count >= adj_start && instr_count <= end) {
            m.should_trace = true;
            m.idx          = i;
            m.is_warmup    = (adj_start < start && instr_count < start);
            return m;
        }
    }
    return m;
}


static void cpu_loglevel_switch(CPUArchState *env, qemu_log_instr_loglevel_t level);

/*
 * COUNTING mode countdown: user instructions left before the next stop
 * (simpoint start, progress report or shutdown). Generated code subtracts
 * each user-mode TB's instruction count at TB entry (gen_tb_start) and exits
 * the TB instead when it would go negative; see
 * qemu_simpoint_handle_countdown_exit().
 */
int32_t qemu_simpoint_countdown = INT32_MAX;

/* Instructions left in the countdown (parked value while paused). */
static uint64_t simpoint_countdown_remaining(void)
{
    if (sp_state.paused) {
        return sp_state.paused_remaining;
    }
    return (uint64_t)qatomic_read(&qemu_simpoint_countdown) +
           sp_state.countdown_overflow;
}

/* Current user instruction count while in COUNTING mode. */
static uint64_t simpoint_current_insn_count(void)
{
    return sp_state.next_stop - simpoint_countdown_remaining();
}

/*
 * Set the countdown to @remaining: up to INT32_MAX in the 32-bit counter,
 * the rest in countdown_overflow. While paused (filter=process, another
 * process is running) the value is parked instead and the live counter is
 * set to INT32_MAX, so counting TBs run by other processes change nothing.
 */
static void simpoint_set_countdown(uint64_t remaining)
{
    int32_t chunk = remaining > INT32_MAX ? INT32_MAX : (int32_t)remaining;

    if (sp_state.paused) {
        sp_state.paused_remaining = remaining;
        sp_state.countdown_overflow = 0;
        qatomic_set(&qemu_simpoint_countdown, INT32_MAX);
        return;
    }
    sp_state.countdown_overflow = remaining - chunk;
    qatomic_set(&qemu_simpoint_countdown, chunk);
}

/* Subtract @n user instructions that ran without the inline check. */
static void simpoint_countdown_subtract(uint64_t n)
{
    uint64_t remaining = simpoint_countdown_remaining();

    simpoint_set_countdown(remaining > n ? remaining - n : 0);
}

/* One past the end of the last simpoint interval (shutdown point). */
static uint64_t simpoint_end_of_last_interval(void)
{
    uint64_t last = 0;

    for (int i = 0; i < simpoints->len; i++) {
        last = MAX(last, g_array_index(simpoints, uint64_t, i));
    }
    return last + INTERVAL_SIZE;
}

/*
 * Progress reporting. Between simpoints (COUNTING mode, no tracing) this
 * prints once per INTERVAL_SIZE user instructions: every interval boundary
 * is scheduled as a stop, which costs one exit to the main loop per
 * interval. A traced window prints every SIMPOINT_TRACE_PROGRESS_STEPS-th
 * of the window.
 */
#define SIMPOINT_TRACE_PROGRESS_STEPS 10

static bool simpoint_bbv_mode(void);

static void simpoint_progress(const char *phase, uint64_t count)
{
    if (simpoint_bbv_mode()) {
        fprintf(stderr, "[simpoint] %-12s %" PRIu64 " insns (interval %"
                PRIu64 ")\n", phase, count, count / INTERVAL_SIZE);
        return;
    }
    fprintf(stderr, "[simpoint] %-12s %" PRIu64 " insns (interval %" PRIu64
            " of %" PRIu64 ")\n",
            phase, count, count / INTERVAL_SIZE,
            simpoint_end_of_last_interval() / INTERVAL_SIZE);
}

/*
 * Built-in BBV collection (-simpoints bbv=FILE).
 *
 * Counting TBs add their instruction count to a per-TB counter cell in
 * generated code (summed by block key at each boundary, see below), see
 * gen_tb_start_simpoint(); the add is masked with qemu_simpoint_bbv_mask so
 * it counts nothing while not counting (or while our program is switched
 * out with filter=process). The countdown stops exactly at every interval
 * boundary, where simpoint_bbv_dump() writes one vector and clears the
 * counters. Interval k therefore covers exactly the same instructions as a
 * SimPoint window at interval k in a tracing run.
 *
 * Block ids are assigned when a block first appears in a written vector,
 * new blocks in PC order, so they don't depend on translation order or on
 * blocks only other processes ran.
 */
/*
 * One counter cell per translated counting TB: generated code adds the TB's
 * charge to cell->weight. At an interval boundary the cells are summed by
 * the block key chosen with -simpoints bbvkey=:
 *   start     the TB's first instruction (default; what the bbv plugin uses)
 *   end       the TB's last instruction: a TB that starts mid-block (retry
 *             after a page fault) ends at the same branch as the full block
 *             and gets the same key
 *   startend  first and last instruction together
 *   all       writes all three: FILE (start), FILE.end, FILE.startend
 */
typedef struct {
    uint64_t weight;   /* instructions in the current interval (TB adds) */
    uint64_t start;    /* PC of the first instruction */
    uint64_t end;      /* PC of the last instruction */
} SimpointBBVCell;

typedef enum {
    BBV_KEY_START,
    BBV_KEY_END,
    BBV_KEY_STARTEND,
} SimpointBBVKey;

typedef struct {
    uint64_t key;
    uint64_t start, end;   /* first cell seen with this key (for .blocks) */
    uint64_t weight;
    uint32_t id;           /* 0 until first written */
} SimpointBBVBlock;

typedef struct {
    SimpointBBVKey kind;
    char *path;
    gzFile out;
    GHashTable *blocks;    /* key -> SimpointBBVBlock */
    uint32_t next_id;
} SimpointBBVOut;

uint64_t qemu_simpoint_bbv_mask;
static GPtrArray *bbv_cells;              /* SimpointBBVCell, never freed */
static SimpointBBVCell *bbv_translating;  /* cell of the TB being translated */
static SimpointBBVOut bbv_outs[3];
static int bbv_nouts;
static uint64_t bbv_intervals;

static bool simpoint_bbv_mode(void)
{
    return SIMPOINT_BBV_PATH != NULL;
}

static bool simpoint_bbv_is_open(void)
{
    return bbv_nouts > 0 && bbv_outs[0].out;
}

/* Translation time: a new counter cell for the TB starting at @pc, or NULL. */
uint64_t *qemu_simpoint_bbv_counter(uint64_t pc)
{
    SimpointBBVCell *c;

    if (!simpoint_bbv_mode() || !bbv_cells) {
        return NULL;
    }
    c = g_new0(SimpointBBVCell, 1);
    c->start = c->end = pc;
    g_ptr_array_add(bbv_cells, c);
    bbv_translating = c;
    return &c->weight;
}

void qemu_simpoint_bbv_tb_begin(void)
{
    bbv_translating = NULL;
}

/* Translation done: record the TB's last instruction; returns its cell. */
void *qemu_simpoint_bbv_tb_done(uint64_t last_pc)
{
    SimpointBBVCell *c = bbv_translating;

    bbv_translating = NULL;
    if (c) {
        c->end = last_pc;
    }
    return c;
}

static uint64_t simpoint_bbv_key(SimpointBBVKey kind, const SimpointBBVCell *c)
{
    switch (kind) {
    case BBV_KEY_START:
        return c->start;
    case BBV_KEY_END:
        return c->end;
    default:
        return (c->start * 0x9E3779B97F4A7C15ULL) ^ c->end;
    }
}

static gint simpoint_bbv_cmp_pc(gconstpointer a, gconstpointer b, gpointer data)
{
    const SimpointBBVBlock *x = *(SimpointBBVBlock *const *)a;
    const SimpointBBVBlock *y = *(SimpointBBVBlock *const *)b;
    SimpointBBVKey kind = GPOINTER_TO_INT(data);
    uint64_t xa = kind == BBV_KEY_END ? x->end : x->start;
    uint64_t ya = kind == BBV_KEY_END ? y->end : y->start;
    uint64_t xb = kind == BBV_KEY_END ? x->start : x->end;
    uint64_t yb = kind == BBV_KEY_END ? y->start : y->end;

    if (xa != ya) {
        return xa < ya ? -1 : 1;
    }
    return xb < yb ? -1 : xb > yb;
}

static gint simpoint_bbv_cmp_weight(gconstpointer a, gconstpointer b)
{
    const SimpointBBVBlock *x = *(SimpointBBVBlock *const *)a;
    const SimpointBBVBlock *y = *(SimpointBBVBlock *const *)b;
    if (x->weight != y->weight) {
        return x->weight > y->weight ? -1 : 1;
    }
    return x->id < y->id ? -1 : x->id > y->id;
}

static void simpoint_bbv_dump_one(SimpointBBVOut *o)
{
    GPtrArray *used = g_ptr_array_new();
    GPtrArray *fresh = g_ptr_array_new();
    GHashTableIter it;
    gpointer key, val;

    for (guint i = 0; i < bbv_cells->len; i++) {
        SimpointBBVCell *c = g_ptr_array_index(bbv_cells, i);
        uint64_t k;
        SimpointBBVBlock *b;

        if (!c->weight) {
            continue;
        }
        k = simpoint_bbv_key(o->kind, c);
        b = g_hash_table_lookup(o->blocks, &k);
        if (!b) {
            b = g_new0(SimpointBBVBlock, 1);
            b->key = k;
            b->start = c->start;
            b->end = c->end;
            g_hash_table_insert(o->blocks, &b->key, b);
        }
        b->weight += c->weight;
    }

    g_hash_table_iter_init(&it, o->blocks);
    while (g_hash_table_iter_next(&it, &key, &val)) {
        SimpointBBVBlock *b = val;
        if (b->weight) {
            g_ptr_array_add(used, b);
            if (!b->id) {
                g_ptr_array_add(fresh, b);
            }
        }
    }
    g_ptr_array_sort_with_data(fresh, simpoint_bbv_cmp_pc,
                               GINT_TO_POINTER(o->kind));
    for (guint i = 0; i < fresh->len; i++) {
        ((SimpointBBVBlock *)g_ptr_array_index(fresh, i))->id = ++o->next_id;
    }
    g_ptr_array_sort(used, simpoint_bbv_cmp_weight);

    gzputc(o->out, 'T');
    for (guint i = 0; i < used->len; i++) {
        SimpointBBVBlock *b = g_ptr_array_index(used, i);
        gzprintf(o->out, "%s:%u:%" PRIu64, i ? " " : "", b->id, b->weight);
        b->weight = 0;
    }
    gzputc(o->out, '\n');
    if ((bbv_intervals + 1) % 10 == 0) {
        gzflush(o->out, Z_SYNC_FLUSH);
    }
    g_ptr_array_free(used, TRUE);
    g_ptr_array_free(fresh, TRUE);
}

static void simpoint_bbv_dump(void)
{
    for (int i = 0; i < bbv_nouts; i++) {
        simpoint_bbv_dump_one(&bbv_outs[i]);
    }
    for (guint i = 0; i < bbv_cells->len; i++) {
        ((SimpointBBVCell *)g_ptr_array_index(bbv_cells, i))->weight = 0;
    }
    bbv_intervals++;
}

/* Write the block maps (id -> PCs) and close the outputs. */
static void simpoint_bbv_close(void)
{
    if (!simpoint_bbv_is_open()) {
        return;
    }
    qemu_simpoint_bbv_mask = 0;
    for (int i = 0; i < bbv_nouts; i++) {
        SimpointBBVOut *o = &bbv_outs[i];
        g_autofree char *map_path = g_strdup_printf("%s.blocks", o->path);
        FILE *map;
        GHashTableIter it;
        gpointer key, val;

        gzclose(o->out);
        o->out = NULL;
        map = fopen(map_path, "w");
        if (map) {
            g_hash_table_iter_init(&it, o->blocks);
            while (g_hash_table_iter_next(&it, &key, &val)) {
                SimpointBBVBlock *b = val;
                if (!b->id) {
                    continue;
                }
                if (o->kind == BBV_KEY_START) {
                    fprintf(map, "%u 0x%" PRIx64 "\n", b->id, b->start);
                } else if (o->kind == BBV_KEY_END) {
                    fprintf(map, "%u 0x%" PRIx64 "\n", b->id, b->end);
                } else {
                    fprintf(map, "%u 0x%" PRIx64 " 0x%" PRIx64 "\n", b->id,
                            b->start, b->end);
                }
            }
            fclose(map);
        }
        fprintf(stderr, "SimPoint BBV: %" PRIu64 " intervals, %u blocks "
                "written to %s (partial last interval discarded)\n",
                bbv_intervals, o->next_id, o->path);
    }
}

static void simpoint_bbv_add_out(SimpointBBVKey kind, const char *suffix)
{
    SimpointBBVOut *o = &bbv_outs[bbv_nouts++];

    o->kind = kind;
    o->path = g_strdup_printf("%s%s", SIMPOINT_BBV_PATH, suffix);
    o->blocks = g_hash_table_new(g_int64_hash, g_int64_equal);
    o->next_id = 0;
    o->out = gzopen(o->path, "w");
    if (!o->out) {
        fprintf(stderr, "SimPoint BBV: cannot open %s\n", o->path);
        exit(1);
    }
}

static void simpoint_bbv_open(void)
{
    const char *k = SIMPOINT_BBV_KEY ? SIMPOINT_BBV_KEY : "start";

    if (simpoint_bbv_is_open()) {
        return;
    }
    if (!bbv_cells) {
        bbv_cells = g_ptr_array_new();
        atexit(simpoint_bbv_close);
    }
    bbv_nouts = 0;
    if (!strcmp(k, "end")) {
        simpoint_bbv_add_out(BBV_KEY_END, "");
    } else if (!strcmp(k, "startend")) {
        simpoint_bbv_add_out(BBV_KEY_STARTEND, "");
    } else if (!strcmp(k, "all")) {
        simpoint_bbv_add_out(BBV_KEY_START, "");
        simpoint_bbv_add_out(BBV_KEY_END, ".end");
        simpoint_bbv_add_out(BBV_KEY_STARTEND, ".startend");
    } else {
        simpoint_bbv_add_out(BBV_KEY_START, "");
    }
}

/* Counting adds are live exactly while counting our program. */
static void simpoint_bbv_update_mask(void)
{
    bool on = simpoint_bbv_mode() && simpoint_bbv_is_open() &&
              sp_state.mode == SIMPOINT_MODE_COUNTING && !sp_state.paused;

    qemu_simpoint_bbv_mask = on ? UINT64_MAX : 0;
}

/*
 * Set the countdown so execution stops at the next event after @count user
 * instructions: the next (warmup-adjusted) simpoint start, the shutdown
 * point after the last simpoint, or the next interval boundary (progress
 * report), whichever comes first. If @count is already inside an interval,
 * stop at once.
 */
static void simpoint_schedule_next_stop(uint64_t count)
{
    uint64_t target;

    if (simpoint_bbv_mode()) {
        target = (count / INTERVAL_SIZE + 1) * INTERVAL_SIZE;
    } else if (find_active_interval(count).should_trace) {
        target = count;
    } else {
        uint64_t last_end = simpoint_end_of_last_interval();
        uint64_t next_tick = (count / INTERVAL_SIZE + 1) * INTERVAL_SIZE;

        target = count > last_end ? count : last_end + 1;
        for (int i = 0; i < adjusted_simpoints->len; i++) {
            uint64_t adj = g_array_index(adjusted_simpoints, uint64_t, i);
            if (adj > count && adj < target) {
                target = adj;
            }
        }
        if (next_tick < target) {
            target = next_tick;
        }
    }

    sp_state.next_stop = target;
    simpoint_set_countdown(target - count);
}

/*
 * All SimPoint mode changes go through here so CF_SIMPOINT_COUNTDOWN (and
 * with it the inline countdown check) is on exactly while in COUNTING mode.
 * Because the bit is part of the TB lookup key, TBs translated with and
 * without the check are never mixed up, flush or no flush.
 */
static void simpoint_set_mode(CPUArchState *env, simpoint_mode_t mode)
{
    bool counting = (mode == SIMPOINT_MODE_COUNTING) && simpoints;
    CPUState *cpu;

    if (sp_state.mode == SIMPOINT_MODE_COUNTING &&
        mode != SIMPOINT_MODE_COUNTING && simpoints) {
        sp_state.instr_count = simpoint_current_insn_count();
    }

    /* PC-based simpoints: see window_faults. Always 0 in interval mode. */
    if (sp_state.mode == SIMPOINT_MODE_TRACING &&
        mode != SIMPOINT_MODE_TRACING) {
        sp_state.instr_count += sp_state.window_faults;
    }
    if (mode == SIMPOINT_MODE_TRACING && sp_state.mode != SIMPOINT_MODE_TRACING) {
        sp_state.window_faults = 0;
    }

    sp_state.mode = mode;

    if (counting) {
        simpoint_schedule_next_stop(sp_state.instr_count);
    } else {
        qatomic_set(&qemu_simpoint_countdown, INT32_MAX);
        sp_state.countdown_overflow = 0;
    }

    CPU_FOREACH(cpu) {
        if (counting) {
            cpu->tcg_cflags |= CF_SIMPOINT_COUNTDOWN;
        } else {
            cpu->tcg_cflags &= ~CF_SIMPOINT_COUNTDOWN;
        }
    }
    simpoint_bbv_update_mask();
}

/*
 * Set while do_cpu_loglevel_switch() commits the instruction that was
 * pending when user-only logging was paused. That instruction executed in
 * user mode, but by the time the deferred commit runs the CPU has already
 * trapped (interrupt, ecall, fault), so cpu_in_user_mode() says otherwise.
 */
static bool sp_deferred_user_commit;

/* Did the instruction being committed execute in user mode? */
static bool simpoint_commit_is_user(CPUArchState *env)
{
    return sp_deferred_user_commit || cpu_in_user_mode(env);
}

/*
 * Did the instruction pending commit fail to retire because of a
 * synchronous exception? SimPoint counts (COUNTING, BBVs, traced windows)
 * and traces retired instructions only, so such an instruction is neither
 * counted nor traced; when it is retried after the handler, the retry is.
 *  - Instruction-fetch faults are raised before the next instruction
 *    starts, so the pending instruction (the last one of the previous TB)
 *    did complete.
 *  - ecall / ebreak raise an exception and do not retire either (they
 *    don't increment minstret), so they are neither counted nor traced;
 *    the COUNTING side doesn't charge them (translator_note_unretired()).
 * Interrupts are only taken between instructions.
 */
static bool simpoint_pending_insn_faulted(cpu_log_instr_info_t *iinfo)
{
    if (!(iinfo->flags & LI_FLAG_INTR_TRAP))
        return false;
#ifdef TARGET_RISCV
    switch (iinfo->intr_code) {
    case RISCV_EXCP_INST_ACCESS_FAULT:
    case RISCV_EXCP_INST_PAGE_FAULT:
    case RISCV_EXCP_INST_GUEST_PAGE_FAULT:
        return false;
    }
#endif
    return true;
}

static bool handle_interval_simpoints(CPUArchState *env, cpu_log_instr_info_t *iinfo)
{
    if (!simpoint_commit_is_user(env))
        return false;
 
    interval_match_t m = find_active_interval(sp_state.instr_count);
    sp_state.instr_count++;
 
    if (m.should_trace) {
        if (sp_state.mode != SIMPOINT_MODE_TRACING) {
            /*
             * Starting a new simpoint. Normally the per-TB path
             * already transitioned us, but handle the edge case
             * where we get here first.
             */
            simpoint_open_trace(env, m.idx, m.is_warmup);
            simpoint_set_mode(env, SIMPOINT_MODE_TRACING);
            sp_state.in_warmup   = m.is_warmup;
            sp_state.current_idx = m.idx;
 
        } else if (m.idx != sp_state.current_idx) {
            /* Switching between adjacent/overlapping simpoints */
            fprintf(stderr, "Switching from SimPoint %d to %d (Warmup: %s)\n",
                    sp_state.current_idx, m.idx,
                    m.is_warmup ? "yes" : "no");

            simpoint_open_trace(env, m.idx, m.is_warmup);
            sp_state.current_idx = m.idx;
            sp_state.in_warmup   = m.is_warmup;
 
        } else if (sp_state.in_warmup && !m.is_warmup) {
            /* transition from warmup to simpoint tracing*/
            fprintf(stderr, "Ending Warmup for SimPoint %d\n",
                    sp_state.current_idx);
            sp_state.in_warmup = false;
        }

        /* Progress through the traced window (warmup included). */
        {
            uint64_t adj = g_array_index(adjusted_simpoints, uint64_t, m.idx);
            uint64_t end = g_array_index(simpoints, uint64_t, m.idx) +
                           INTERVAL_SIZE;
            uint64_t step = MAX((end - adj) / SIMPOINT_TRACE_PROGRESS_STEPS, 1);
            uint64_t done = sp_state.instr_count - adj;

            if (done % step == 0 && done < end - adj) {
                char phase[32];
                snprintf(phase, sizeof(phase), "%s sp%d %2" PRIu64 "%%",
                         m.is_warmup ? "warmup" : "trace", m.idx,
                         done * 100 / (end - adj));
                simpoint_progress(phase, sp_state.instr_count);
            }
        }

        return true;  /* emit this instruction */
 
    } else if (sp_state.mode == SIMPOINT_MODE_TRACING) {
        
        // Exit the simpoint region.  
        int finished_idx = sp_state.current_idx;
        simpoint_end(env, simpoints->len - 1);
 
        if (!sp_state.stop) {
            /*
             * More simpoints remain. Disable CF_LOG_INSTR so TBs
             * recompile without logging overhead. 
             */
            simpoint_set_mode(env, SIMPOINT_MODE_COUNTING);
            cpu_loglevel_switch(env, QEMU_LOG_INSTR_LOGLEVEL_NONE);
 
            fprintf(stderr,
                    "SimPoint %d ended, counting mode at icount=%" PRIu64 "\n",
                    finished_idx, sp_state.instr_count - 1);

            tb_flush(env_cpu(env));
        } else {
            
             //All SimPoints done. Shut down.
            simpoint_set_mode(env, SIMPOINT_MODE_INACTIVE);
            cpu_loglevel_switch(env, QEMU_LOG_INSTR_LOGLEVEL_NONE);
            fprintf(stderr,
                    "SimPoint tracing complete at %" PRIu64
                    " instructions. Shutting down\n",
                    sp_state.instr_count - 1);
            qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
        }
    }
 
    return false;
}


static bool handle_pc_simpoints(CPUArchState *env, cpu_log_instr_state_t *cpulog, cpu_log_instr_info_t *iinfo)
{
    if (iinfo->pc != 0) {
        if (!pc_exec_count_map) {
            pc_exec_count_map = g_hash_table_new_full(
                g_direct_hash, g_direct_equal, NULL, g_free);
        }

        uint64_t *count = g_hash_table_lookup(pc_exec_count_map,
                                              GSIZE_TO_POINTER(iinfo->pc));
        if (!count) {
            count = g_malloc0(sizeof(uint64_t));
            g_hash_table_insert(pc_exec_count_map,
                                GSIZE_TO_POINTER(iinfo->pc), count);
        }

        if (sp_state.mode != SIMPOINT_MODE_TRACING) {
            for (int i = 0; i < simpoint_pcs->len; i++) {
                simpoint_pc_entry_t *entry = &g_array_index(simpoint_pcs,
                                                           simpoint_pc_entry_t, i);
                if (iinfo->pc == entry->pc && *count == entry->execution_count) {
                    simpoint_open_trace(env, i, false);
                    simpoint_set_mode(env, SIMPOINT_MODE_TRACING);
                    sp_state.current_idx      = i;
                    cpulog->simpoint_insn_count = 0;
                    break;
                }
            }
        }
        (*count)++;
    }
    
    if (sp_state.mode == SIMPOINT_MODE_TRACING) {
        if (cpulog->simpoint_insn_count >= INTERVAL_SIZE) {
            simpoint_end(env, simpoint_pcs->len - 1);
            cpulog->simpoint_insn_count = 0;
            return false;
        }
        cpulog->simpoint_insn_count++;
        return true;
    }

    return false;
}

static void emit_with_dfilter(CPUArchState *env, cpu_log_instr_info_t *iinfo)
{
    if (!debug_regions) {
        emit_entry_event(env, iinfo);
        return;
    }

    for (int i = 0; i < debug_regions->len; i++) {
        Range *range = &g_array_index(debug_regions, Range, i);

        if (range_contains(range, iinfo->pc)) {
            emit_entry_event(env, iinfo);
            return;
        }
        for (int j = 0; j < iinfo->mem->len; j++) {
            log_meminfo_t *minfo = &g_array_index(iinfo->mem, log_meminfo_t, j);
            if (range_contains(range, minfo->addr)) {
                emit_entry_event(env, iinfo);
                return;
            }
        }
    }
}

/* Common instruction commit implementation */
static void do_instr_commit(CPUArchState *env)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);
    cpu_log_instr_info_t *iinfo = get_cpu_log_instr_info(env);

    log_assert(cpulog != NULL && "Invalid log state");
    log_assert(iinfo != NULL && "Invalid log info");

    if (cpulog->force_drop)
        return;

    if (cpulog->starting) {
        cpulog->starting = false;
        emit_start_event(env, cpu_get_recent_pc(env));
        return;
    }

    if (sp_state.stop)
        return;

    /*
     * In non-tracing simpoint modes, CF_LOG_INSTR should be OFF for
     * both CHERI and non-CHERI. If we somehow get here, just bail.
     * (Cap store tracking is handled by the direct hooks now.)
     */
    if (sp_state.mode == SIMPOINT_MODE_COUNTING) {
        /*
         * A logging TB is still running just after a simpoint ended,
         * before the log-level switch and TB flush take effect. These
         * instructions did execute, and such TBs carry no inline countdown
         * check (see qemu_simpoint_tb_needs_countdown), so subtract them
         * here using the same rule handle_interval_simpoints() uses.
         */
        if (simpoints && simpoint_commit_is_user(env))
            simpoint_countdown_subtract(1);
        return;
    }
    if (sp_state.mode == SIMPOINT_MODE_WAIT_START_PC || 
        sp_state.mode == SIMPOINT_MODE_STEPPING_TO_START) {
        return;
    }

    /*
     * Never write a record for an instruction whose PC was not captured.
     * The per-instruction log helpers only fill iinfo while the log level
     * is active, but a logging TB still calls the commit helper after
     * logging was switched off underneath it (e.g. the qtrace per-thread
     * stop the kernel issues when the traced thread is switched out).
     * Such a record would be all zeros (ip=0) and would also be counted
     * as part of the SimPoint window, so drop it without counting it.
     */
    if (iinfo->pc == 0) {
        static uint64_t dropped_no_pc;

        dropped_no_pc++;
        if ((dropped_no_pc & (dropped_no_pc - 1)) == 0 ||
            (dropped_no_pc & ((1u << 20) - 1)) == 0) {
            fprintf(stderr,
                    "[log_instr] dropped %" PRIu64 " instruction record(s) "
                    "with no PC (logging was off when they executed)\n",
                    dropped_no_pc);
        }
        return;
    }
    
    /* SimPoint dispatch */
    bool should_emit = true;

    if (simpoint_pcs) {
        should_emit = handle_pc_simpoints(env, cpulog, iinfo);
    } else if (simpoints) {
        should_emit = handle_interval_simpoints(env, iinfo);
    }

    if (!should_emit)
        return;

    if ((simpoint_pcs || simpoints) && !sp_state.file_open)
        return;

    emit_with_dfilter(env, iinfo);
}


/*
 * Perform the actual work to change per-CPU log level.
 * This runs in the CPU exclusive context.
 *
 * Note:
 * If we start logging, we delay emitting the start event until the next commit.
 * This is because on the path from the exclusive context to the translation
 * loop we may get an interrupt/exception causing a switch in CPU mode, causing
 * to stop logging. This would result in a pointless start/stop sequence with
 * no instructions executed in between.
 */
static void do_cpu_loglevel_switch(CPUState *cpu, run_on_cpu_data data)
{
    CPUArchState *env = cpu->env_ptr;
    tcg_debug_assert(env != NULL && "Called to early?");
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);
    cpu_log_instr_info_t *iinfo = get_cpu_log_instr_info(env);
    qemu_log_instr_loglevel_t prev_level = cpulog->loglevel;
    bool prev_level_active = cpulog->loglevel_active;
    qemu_log_instr_loglevel_t next_level = data.host_int;
    bool next_level_active;

    /* Decide whether we have to pause/resume logging */
    switch (next_level) {
    case QEMU_LOG_INSTR_LOGLEVEL_NONE:
        next_level_active = false;
        break;
    case QEMU_LOG_INSTR_LOGLEVEL_ALL:
        next_level_active = true;
        break;
    case QEMU_LOG_INSTR_LOGLEVEL_USER:
        /*
         * Assume iinfo holds the mode switch that caused cpu_loglevel_switch
         * to be called
         */
        if (iinfo->flags & LI_FLAG_MODE_SWITCH)
            next_level_active = (iinfo->next_cpu_mode == QEMU_LOG_INSTR_CPU_USER);
        else
            next_level_active = cpu_in_user_mode(env);
        break;
    default:
        log_assert(false && "Invalid cpu instruction log level");
        warn_report("Invalid cpu %d instruction log level\r",
                    cpu->cpu_index);
    }

    /* Update level */
    cpulog->loglevel = next_level;
    cpulog->loglevel_active = next_level_active;

    /* Check if this was a no-op */
    if (next_level == prev_level && prev_level_active == next_level_active)
        return;

    /* Flushing all translations makes things incredibly slow. Instead,
     * we put whether tracing is currently enabled into cflags */

    /* Emit start/stop events */
    if (prev_level_active) {
        if (cpulog->starting) {
            /*
             * Nothing logged yet since the last start. reset_log_buffer()
             * clears 'starting'; keep it if logging stays active (e.g.
             * ALL -> USER when a later SimPoint reopens the log), or the
             * first commit logs and counts an empty entry.
             */
            reset_log_buffer(cpulog, iinfo);
            cpulog->starting = next_level_active;
            return;
        }
        /*
         * With user-only logging, an active log level means the pending
         * instruction ran in user mode, even though we are switching away
         * from it now. Without this, SimPoint drops (and doesn't count)
         * the last instruction before every trap.
         */
        if ((simpoints || simpoint_pcs) &&
            (sp_state.mode == SIMPOINT_MODE_TRACING ||
             sp_state.mode == SIMPOINT_MODE_COUNTING) &&
            simpoint_pending_insn_faulted(iinfo)) {
            /*
             * The pending instruction raised an exception and did not
             * retire (page fault, CHERI fault, illegal instruction, ecall,
             * ebreak, ...):
             * it is neither traced nor counted, in a traced window or in a
             * logging TB still running just after one (COUNTING). The
             * countdown and the BBVs don't count it either, so a window of
             * N instructions holds exactly the N retired instructions of
             * BBV interval k. PC-based simpoints keep adding these back to
             * instr_count when the window ends (see simpoint_set_mode).
             */
            if (simpoint_pcs && sp_state.mode == SIMPOINT_MODE_TRACING) {
                sp_state.window_faults++;
            }
        } else {
            sp_deferred_user_commit =
                (prev_level == QEMU_LOG_INSTR_LOGLEVEL_USER);
            do_instr_commit(env);
            sp_deferred_user_commit = false;
        }
        emit_stop_event(env, cpu_get_recent_pc(env));
        /* Instruction commit may have advanced to the next iinfo buffer slot */
        iinfo = get_cpu_log_instr_info(env);
        reset_log_buffer(cpulog, iinfo);
    }
    if (next_level_active) {
        cpulog->starting = true;
    }
}

static void cpu_loglevel_switch(CPUArchState *env,
    qemu_log_instr_loglevel_t level)
{
    async_safe_run_on_cpu(env_cpu(env), do_cpu_loglevel_switch,
        RUN_ON_CPU_HOST_INT(level));
}

/* Start global logging flag if it was disabled */
static void global_loglevel_enable(void)
{
    if (!qemu_loglevel_mask(CPU_LOG_INSTR))
        qemu_set_log_internal(qemu_loglevel | CPU_LOG_INSTR);
}

/*
 * Handle global logging switch, triggered by the qemu monitor or
 * other external events.
 * This runs in the CPU exclusive context.
 */
static void do_global_loglevel_switch(CPUState *cpu, run_on_cpu_data data)
{
    qemu_log_instr_loglevel_t level = data.host_int;

    if (level != QEMU_LOG_INSTR_LOGLEVEL_NONE)
        global_loglevel_enable();
    /*
     * TODO(am2419): To do things cleanly, we should clear the CPU_LOG_INSTR
     * flag when stopping, however to do this we would need to keep track
     * of the number of CPUs that we have disabled so far, so that we only
     * clear the flag on the last CPU.
     * qemu_set_log_internal(qemu_loglevel & (~CPU_LOG_INSTR));
     */
    do_cpu_loglevel_switch(cpu, RUN_ON_CPU_HOST_INT(level));
}

/*
 * Interface for the monitor to start and stop tracing on all CPUs.
 * Note: It is critical that when stopping we delay the stop until
 * all the CPUs have exited their TCG exec loop. This will happen when
 * the current TB is finished. If we clear the global flag immediately
 * we will end up emitting stale instructions.
 */
int qemu_log_instr_global_switch(int log_flags)
{
    CPUState *cpu;
    qemu_log_instr_loglevel_t level;

    if (log_flags & CPU_LOG_INSTR_U) {
        level = QEMU_LOG_INSTR_LOGLEVEL_USER;
        log_flags |= CPU_LOG_INSTR;
    } else if (log_flags & CPU_LOG_INSTR) {
        level = QEMU_LOG_INSTR_LOGLEVEL_ALL;
    } else {
        level = QEMU_LOG_INSTR_LOGLEVEL_NONE;
    }

    CPU_FOREACH(cpu) {
        async_safe_run_on_cpu(cpu, do_global_loglevel_switch,
            RUN_ON_CPU_HOST_INT(level));
    }

    return log_flags;
}

/*
 * Initialize instruction info entry from the ring buffer.
 */
static void qemu_log_instr_info_init(cpu_log_instr_info_t *iinfo)
{
    if (iinfo->txt_buffer == NULL)
        iinfo->txt_buffer = g_string_new(NULL);
    if (iinfo->regs == NULL)
        iinfo->regs = g_array_new(false, true, sizeof(log_reginfo_t));
    if (iinfo->mem == NULL)
        iinfo->mem = g_array_new(false, true, sizeof(log_meminfo_t));
}

/*
 * Clear an instruction info entry from the ring buffer.
 */
static void qemu_log_instr_info_destroy(gpointer data)
{
    cpu_log_instr_info_t *iinfo = data;

    g_string_free(iinfo->txt_buffer, TRUE);
    g_array_free(iinfo->regs, TRUE);
    g_array_free(iinfo->mem, TRUE);
}

/*
 * This must be called upon cpu creation.
 * Initializes the per-CPU logging state and data structures.
 *
 * Currently the instruction info ring buffer size is fixed and can not
 * be changed at runtime.
 */
void qemu_log_instr_init(CPUState *cpu)
{
    cpu_log_instr_state_t *cpulog = &cpu->log_state;
    GArray *iinfo_ring = g_array_sized_new(FALSE, TRUE,
        sizeof(cpu_log_instr_info_t), reset_entry_buffer_size);
    cpu_log_instr_info_t *iinfo;
    int i;

    g_array_set_size(iinfo_ring, reset_entry_buffer_size);
    g_array_set_clear_func(iinfo_ring, qemu_log_instr_info_destroy);

    for (i = 0; i < iinfo_ring->len; i++) {
        iinfo = &g_array_index(iinfo_ring, cpu_log_instr_info_t, i);
        qemu_log_instr_info_init(iinfo);
    }

    cpulog->loglevel = QEMU_LOG_INSTR_LOGLEVEL_NONE;
    cpulog->loglevel_active = false;
    cpulog->instr_info = iinfo_ring;
    cpulog->ring_head = 0;
    cpulog->ring_tail = 0;
    reset_log_buffer(cpulog, iinfo);

    // Make sure we are using the correct trace format.
    if (trace_format == NULL) {
        trace_format = &trace_formats[qemu_log_instr_format];
        // Only emit header on first init
        if (trace_format->emit_header)
            trace_format->emit_header(cpu->env_ptr);
    }

    /* If we are starting with instruction logging enabled, switch it on now */
    if (qemu_loglevel_mask(CPU_LOG_INSTR_U))
        do_cpu_loglevel_switch(
            cpu, RUN_ON_CPU_HOST_INT(QEMU_LOG_INSTR_LOGLEVEL_USER));
    else if (qemu_loglevel_mask(CPU_LOG_INSTR))
        do_cpu_loglevel_switch(cpu,
            RUN_ON_CPU_HOST_INT(QEMU_LOG_INSTR_LOGLEVEL_ALL));
}

static void
do_log_buffer_resize(CPUState *cpu, run_on_cpu_data data)
{
    unsigned long new_size = data.host_ulong;
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(cpu->env_ptr);
    cpu_log_instr_info_t *iinfo;
    int i;

    g_array_set_size(cpulog->instr_info, new_size);
    cpulog->ring_head = 0;
    cpulog->ring_tail = 0;
    for (i = 0; i < cpulog->instr_info->len; i++) {
        /*
         * Clear and reinitialize all the entries,
         * a bit overkill but should not be a frequent operation.
         */
        iinfo = &g_array_index(cpulog->instr_info, cpu_log_instr_info_t, i);
        qemu_log_instr_info_init(iinfo);
        reset_log_buffer(cpulog, iinfo);
    }
}

void qemu_log_instr_set_buffer_size(unsigned long new_size)
{
    CPUState *cpu;

    if (new_size < MIN_ENTRY_BUFFER_SIZE) {
        warn_report("New trace entry buffer size is too small < %zu, ignored.\n",
                    (size_t)MIN_ENTRY_BUFFER_SIZE);
        return;
    }

    /* Set this in case this is called from qemu option parsing */
    reset_entry_buffer_size = new_size;
    CPU_FOREACH(cpu) {
        async_safe_run_on_cpu(cpu, do_log_buffer_resize,
            RUN_ON_CPU_HOST_ULONG(new_size));
    }
}

/*
 * Check whether instruction logging is enabled on this CPU.
 */
bool qemu_log_instr_check_enabled(CPUArchState *env)
{
    return (qemu_loglevel_mask(CPU_LOG_INSTR) &&
            get_cpu_log_state(env)->loglevel_active);
}

/*
 * Record a change in CPU mode.
 * Any instruction calling this should exit the TB.
 * This will also trigger pause and resume of user-only logging activity.
 *
 * We flush the TCG buffer when we have to change logging level, this
 * will cause an exit from the cpu_exec() loop, the bulk of the log level
 * switching is performed in exclusive context during the TCG flush
 * initiated here.
 */
void qemu_log_instr_mode_switch(CPUArchState *env,
    qemu_log_instr_cpu_mode_t mode, target_ulong pc)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);
    cpu_log_instr_info_t *iinfo = get_cpu_log_instr_info(env);

    log_assert(cpulog != NULL && "Invalid log state");
    log_assert(iinfo != NULL && "Invalid log info");

    iinfo->flags |= LI_FLAG_MODE_SWITCH;
    iinfo->next_cpu_mode = mode;

    /* If we are not logging in user-only mode, bail */
    if (!qemu_loglevel_mask(CPU_LOG_INSTR) ||
        cpulog->loglevel != QEMU_LOG_INSTR_LOGLEVEL_USER)
        return;

    /* Don't touch CF_LOG_INSTR if simpoint has logging suppressed */
    if (sp_state.mode == SIMPOINT_MODE_COUNTING ||
        sp_state.mode == SIMPOINT_MODE_WAIT_START_PC ||
        sp_state.mode == SIMPOINT_MODE_STEPPING_TO_START)
        return;
        
    /* Check if we are switching to an interesting mode */
    if ((mode == QEMU_LOG_INSTR_CPU_USER) != cpulog->loglevel_active) {
        cpu_loglevel_switch(env, cpulog->loglevel);
    }
}

void qemu_log_instr_drop(CPUArchState *env)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);

    log_assert(cpulog != NULL && "Invalid log state");

    cpulog->force_drop = true;
}

void qemu_log_instr_commit(CPUArchState *env)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);
    cpu_log_instr_info_t *iinfo = get_cpu_log_instr_info(env);

    log_assert(cpulog != NULL && "Invalid log state");
    log_assert(iinfo != NULL && "Invalid log info");

    do_instr_commit(env);
    /* commit may have advanced to the next iinfo buffer slot */
    iinfo = get_cpu_log_instr_info(env);
    reset_log_buffer(cpulog, iinfo);
}

void qemu_log_instr_reg(CPUArchState *env, const char *reg_name, target_ulong value)
{
    cpu_log_instr_info_t *iinfo = get_cpu_log_instr_info(env);
    log_reginfo_t r;

    r.flags = 0;
    r.name = reg_name;
    r.gpr = value;
    g_array_append_val(iinfo->regs, r);
}

void helper_qemu_log_instr_reg(CPUArchState *env, const void *reg_name,
                               target_ulong value)
{
    if (qemu_log_instr_check_enabled(env))
        qemu_log_instr_reg(env, (const char *)reg_name, value);
}

void helper_qemu_log_instr_branch(CPUArchState *env, uint32_t taken, uint32_t branch_type)
{
    if (qemu_log_instr_check_enabled(env)) {
        cpu_log_instr_info_t *iinfo = get_cpu_log_instr_info(env);
        iinfo->is_branch = 1;
        iinfo->branch_taken = taken ? 1 : 0;
        iinfo->branch_type = (qemu_log_branch_type_t)branch_type;
    }
}

void helper_qemu_log_reg_src(CPUArchState *env, uint32_t reg_id, uint32_t reg_type){
    if (qemu_log_instr_check_enabled(env)) {
        cpu_log_instr_info_t *iinfo = get_cpu_log_instr_info(env);
        if (iinfo && iinfo->num_src_regs < 4) {
            qemu_log_reg_info *r = &iinfo->src_regs[iinfo->num_src_regs++];
            r->reg_id = (uint8_t)reg_id;
            r->type = (LogRegType)reg_type;
        }
    }
}

void helper_qemu_log_reg_dst(CPUArchState *env, uint32_t reg_id, uint32_t reg_type){
    if (qemu_log_instr_check_enabled(env)) {
        cpu_log_instr_info_t *iinfo = get_cpu_log_instr_info(env);
        if (iinfo && iinfo->num_dst_regs < 2) {
            qemu_log_reg_info *r = &iinfo->dst_regs[iinfo->num_dst_regs++];
            r->reg_id = (uint8_t)reg_id;
            r->type = (LogRegType)reg_type;
        }
    }
}

#ifdef TARGET_CHERI
void qemu_log_instr_cap(CPUArchState *env, const char *reg_name,
                         const cap_register_t *cr)
{
    cpu_log_instr_info_t *iinfo = get_cpu_log_instr_info(env);
    log_reginfo_t r;

    r.flags = LRI_CAP_REG | LRI_HOLDS_CAP;
    r.name = reg_name;
    r.cap = *cr;
    g_array_append_val(iinfo->regs, r);
}

void helper_qemu_log_instr_cap(CPUArchState *env, const void *reg_name,
                               const void *cr)
{
    if (qemu_log_instr_check_enabled(env))
        qemu_log_instr_cap(env, reg_name, cr);
}

void qemu_log_instr_cap_int(CPUArchState *env, const char *reg_name,
                             target_ulong value)
{
    cpu_log_instr_info_t *iinfo = get_cpu_log_instr_info(env);
    log_reginfo_t r;

    r.flags = LRI_CAP_REG;
    r.name = reg_name;
    r.gpr = value;
    g_array_append_val(iinfo->regs, r);
}


void qemu_log_instr_mem_auth_cap(CPUArchState *env,
                                 const cap_register_t *auth,
                                 uint32_t regnum)
{
    cpu_log_instr_info_t *iinfo = get_cpu_log_instr_info(env);
    iinfo->has_auth_cap = true;
    iinfo->auth_cap = *auth;
    iinfo->auth_cap_regnum = regnum;
}
#endif

static inline void qemu_log_instr_mem_int(CPUArchState *env, target_ulong addr,
                                          int flags, TCGMemOpIdx oi,
                                          target_ulong value)
{
    cpu_log_instr_info_t *iinfo = get_cpu_log_instr_info(env);
    log_meminfo_t m;

    m.flags = flags;
    m.op = get_memop(oi);
    m.addr = addr;
    m.value = value;
    g_array_append_val(iinfo->mem, m);
}

void qemu_log_instr_ld_int(CPUArchState *env, target_ulong addr, TCGMemOpIdx oi,
                           target_ulong value)
{
    qemu_log_instr_mem_int(env, addr, LMI_LD, oi, value);
}

void qemu_log_instr_st_int(CPUArchState *env, target_ulong addr, TCGMemOpIdx oi,
                           target_ulong value)
{
    qemu_log_instr_mem_int(env, addr, LMI_ST, oi, value);
}

#ifdef TARGET_CHERI
/*
 * Note: logging the value here may be redundant as the capability is
 * generally loaded to a register and we get the value in the reginfo
 * as well. Need to think whether there is value to keep logging what
 * was loaded directly.
 */

static inline void qemu_log_instr_mem_cap(
    CPUArchState *env, target_ulong addr, int flags,
    const cap_register_t *value)
{
    cpu_log_instr_info_t *iinfo = get_cpu_log_instr_info(env);
    log_meminfo_t m;

    m.flags = flags;
    m.op = 0;
    m.addr = addr;
    m.cap = *value;
    g_array_append_val(iinfo->mem, m);  
}

/*
 * Forget the most recent memory access recorded for the current instruction.
 * For emulator-internal accesses that are not architectural, e.g. the
 * compare-read SC.C uses to check its reservation.
 */
void qemu_log_instr_drop_last_mem(CPUArchState *env)
{
    cpu_log_instr_info_t *iinfo = get_cpu_log_instr_info(env);

    if (iinfo->mem->len > 0)
        g_array_set_size(iinfo->mem, iinfo->mem->len - 1);
}

void qemu_log_instr_ld_cap(CPUArchState *env, target_ulong addr,
                           const cap_register_t *value)
{
    qemu_log_instr_mem_cap(env, addr, LMI_LD | LMI_CAP, value);
}
void qemu_log_instr_st_cap(CPUArchState *env, target_ulong addr,
                           const cap_register_t *value)
{
    qemu_log_instr_mem_cap(env, addr, LMI_ST | LMI_CAP, value);
}
#endif

void qemu_log_instr(CPUArchState *env, target_ulong pc, const char *insn,
                    uint32_t size)
{
    cpu_log_instr_info_t *iinfo = get_cpu_log_instr_info(env);

    iinfo->pc = pc;
    iinfo->insn_size = size;
    memcpy(iinfo->insn_bytes, insn, size);
}

void qemu_log_instr_asid(CPUArchState *env, uint16_t asid)
{
    cpu_log_instr_info_t *iinfo = get_cpu_log_instr_info(env);

    iinfo->asid = asid;
}

void qemu_log_instr_exception(CPUArchState *env, uint32_t code,
                              target_ulong vector, target_ulong faultaddr)
{
    cpu_log_instr_info_t *iinfo = get_cpu_log_instr_info(env);

    iinfo->flags |= LI_FLAG_INTR_TRAP;
    iinfo->intr_code = code;
    iinfo->intr_vector = vector;
    iinfo->intr_faultaddr = faultaddr;
}

void qemu_log_instr_interrupt(CPUArchState *env, uint32_t code,
                              target_ulong vector)
{
    cpu_log_instr_info_t *iinfo = get_cpu_log_instr_info(env);

    iinfo->flags |= LI_FLAG_INTR_ASYNC;
    iinfo->intr_code = code;
    iinfo->intr_vector = vector;
}

void qemu_log_instr_evt(CPUArchState *env, uint16_t fn, target_ulong arg0,
                         target_ulong arg1, target_ulong arg2,
                         target_ulong arg3)
{
    /* iinfo->cv_buffer.entry_type = CVT_EVT; */
    /* iinfo->cv_buffer.val5 = fn; */
    /* iinfo->cv_buffer.val1 = arg0; */
    /* iinfo->cv_buffer.val2 = arg1; */
    /* iinfo->cv_buffer.val3 = arg2; */
    /* iinfo->cv_buffer.val4 = arg3; */
}

void qemu_log_instr_extra(CPUArchState *env, const char *msg, ...)
{
    cpu_log_instr_info_t *iinfo = get_cpu_log_instr_info(env);
    va_list va;

    va_start(va, msg);
    g_string_append_vprintf(iinfo->txt_buffer, msg, va);
    va_end(va);
}


/*
 * Main-loop hook while waiting for / stepping to START_PC.
 *
 * COUNTING mode no longer comes through here: user-mode TBs decrement
 * qemu_simpoint_countdown inline (gen_tb_start) and TB chaining stays on.
 * See qemu_simpoint_handle_countdown_exit() for what happens at a boundary.
 */
void qemu_simpoint_step_to_start_pc(CPUArchState *env, target_ulong tb_pc,
                            uint64_t icount)
{
    CPUState *cpu = env_cpu(env);

    if (!cpu_in_user_mode(env))
        return;

    if (sp_state.mode != SIMPOINT_MODE_STEPPING_TO_START)
        return;

    /* Walking through 1-insn TBs to find exact START_PC; not there yet. */
    if (tb_pc != START_PC) {
        cpu->cflags_next_tb = (curr_cflags(cpu) & ~CF_COUNT_MASK) | 1;
    }
}

/*
 * filter=process support. The traced program is identified by its
 * page-table root (all its threads share it); the kernel changes satp on
 * every switch between processes, so a satp write is exactly the point
 * where our program starts or stops running user code.
 */
static uint64_t simpoint_page_table_root(CPUArchState *env)
{
#ifdef TARGET_RISCV
    target_ulong ppn = riscv_cpu_is_32bit(env) ? (env->satp & SATP32_PPN)
                                               : (env->satp & SATP64_PPN);
    return (uint64_t)ppn << TARGET_PAGE_BITS;
#else
    return 0;
#endif
}

static bool simpoint_filtering(void)
{
    return SIMPOINT_PROCESS_FILTER && sp_state.program_root != 0 &&
           (sp_state.mode == SIMPOINT_MODE_COUNTING ||
            sp_state.mode == SIMPOINT_MODE_TRACING);
}

/* Our program was switched out: stop counting and tracing. */
static void simpoint_pause(CPUArchState *env)
{
    uint64_t remaining = simpoint_countdown_remaining();

    sp_state.paused = true;
    simpoint_bbv_update_mask();
    if (sp_state.mode == SIMPOINT_MODE_COUNTING) {
        simpoint_set_countdown(remaining);      /* parks it */
    } else {
        cpu_loglevel_switch(env, QEMU_LOG_INSTR_LOGLEVEL_NONE);
    }
}

/*
 * Whether logging is compiled into a TB is decided at translation time and
 * is not part of the TB lookup key. While our program is switched out of a
 * traced window, other processes translate user TBs without logging; code
 * on shared pages (libc, rtld, ...) at the same address is then reused by
 * our program after it resumes, and those instructions would be neither
 * traced nor counted. Remember that this happened and flush on resume.
 */
static bool sp_untraced_user_tb;

void qemu_simpoint_note_translation(CPUArchState *env, bool logging)
{
    if (!logging && sp_state.paused &&
        sp_state.mode == SIMPOINT_MODE_TRACING && cpu_in_user_mode(env)) {
        sp_untraced_user_tb = true;
    }
}

/* Our program was switched back in: resume counting and tracing. */
static void simpoint_resume(CPUArchState *env)
{
    sp_state.paused = false;
    simpoint_bbv_update_mask();
    if (sp_state.mode == SIMPOINT_MODE_COUNTING) {
        simpoint_set_countdown(sp_state.paused_remaining);
    } else {
        cpu_loglevel_switch(env, QEMU_LOG_INSTR_LOGLEVEL_USER);
        if (sp_untraced_user_tb) {
            sp_untraced_user_tb = false;
            tb_flush(env_cpu(env));
        }
    }
}

/* Called after every satp write (target/riscv/csr.c). */
void qemu_simpoint_address_space_changed(CPUArchState *env)
{
    bool ours;

    if (!simpoint_filtering()) {
        return;
    }
    ours = simpoint_page_table_root(env) == sp_state.program_root;
    if (ours && sp_state.paused) {
        simpoint_resume(env);
    } else if (!ours && !sp_state.paused) {
        simpoint_pause(env);
    }
}

/*
 * Called before a TB executes. When the 1-insn stepping TB at START_PC is
 * about to run, switch to COUNTING (or straight to TRACING) *before* it
 * executes, so the START_PC instruction is instruction 0, as in the BBV
 * plugin, which starts counting with the TB at the trigger PC. Returns true
 * if the caller must exit the CPU loop so the TB is retranslated under the
 * new mode (with the inline countdown check, or with logging).
 */
bool qemu_simpoint_at_start_pc(CPUArchState *env, target_ulong tb_pc)
{
    if (sp_state.mode != SIMPOINT_MODE_STEPPING_TO_START ||
        tb_pc != START_PC || !cpu_in_user_mode(env))
        return false;

    fprintf(stderr, "START_PC 0x%" PRIx64 " reached\n", START_PC);
    sp_state.instr_count = 0;
    sp_state.paused = false;
    if (SIMPOINT_PROCESS_FILTER) {
        sp_state.program_root = simpoint_page_table_root(env);
        if (sp_state.program_root) {
            fprintf(stderr, "SimPoint filter: tracking the process with page "
                    "table at 0x%" PRIx64 "\n", sp_state.program_root);
        } else {
            fprintf(stderr, "SimPoint filter: paging is off at START_PC, "
                    "filter=process has no effect\n");
        }
    }

    /* Check if interval 0 is immediately a simpoint */
    interval_match_t m = find_active_interval(0);
    if (m.should_trace) {
        simpoint_set_mode(env, SIMPOINT_MODE_TRACING);
        simpoint_open_trace(env, m.idx, m.is_warmup);
        sp_state.in_warmup   = m.is_warmup;
        sp_state.current_idx = m.idx;
        global_loglevel_enable();
        cpu_loglevel_switch(env, QEMU_LOG_INSTR_LOGLEVEL_USER);
        tb_flush(env_cpu(env));
    } else {
        simpoint_set_mode(env, SIMPOINT_MODE_COUNTING);
    }
    return true;
}

bool qemu_simpoint_seeking_start_pc(void)
{
    return sp_state.mode == SIMPOINT_MODE_WAIT_START_PC ||
           sp_state.mode == SIMPOINT_MODE_STEPPING_TO_START;
}

/*
* Some starting pcs may be in the middle of a translation block
* so we check the range of START_PC to detect if we're approaching it
*/
bool qemu_simpoint_tb_contains_start_pc(target_ulong tb_pc, uint32_t tb_size)
{
    return sp_state.mode == SIMPOINT_MODE_WAIT_START_PC &&
           tb_pc <= START_PC && START_PC < tb_pc + tb_size;
}

/*
* Force the next TB to contain exactly 1 instruction.
* This is synchronous — no async tb_flush needed.
* tb_find will see cflags_next_tb and compile accordingly.
*/
void qemu_simpoint_enter_stepping(CPUArchState *env)
{
    fprintf(stderr, "START_PC 0x%" PRIx64 " in TB range, "
            "stepping with 1-insn TBs\n", START_PC);

    simpoint_set_mode(env, SIMPOINT_MODE_STEPPING_TO_START);

    CPUState *cpu = env_cpu(env);
    cpu->cflags_next_tb = (curr_cflags(cpu) & ~CF_COUNT_MASK) | 1;
}

/*
 * Translation-time decision: does this TB get the inline countdown check?
 * CF_SIMPOINT_COUNTDOWN is only in the CPU's cflags while in COUNTING mode,
 * and the privilege level is part of the TB flags, so a TB translated in
 * user mode only ever runs in user mode.
 */
bool qemu_simpoint_tb_needs_countdown(CPUArchState *env, uint32_t cflags)
{
    /*
     * A TB that still logs (translated in the short window before the
     * log-level switch lands) is counted by its commits instead, so it
     * must not also get the inline check.
     */
    return (cflags & CF_SIMPOINT_COUNTDOWN) && cpu_in_user_mode(env) &&
           !qemu_log_instr_enabled(env);
}

/*
 * The countdown reached zero: sp_state.next_stop user instructions have
 * executed. Start tracing, shut down, or report progress and schedule the
 * next stop.
 */
static void simpoint_reached_stop(CPUArchState *env)
{
    uint64_t count = sp_state.next_stop;
    interval_match_t m;

    sp_state.instr_count = count;

    if (simpoint_bbv_mode()) {
        if (count % INTERVAL_SIZE == 0) {
            simpoint_bbv_dump();
            simpoint_progress("bbv", count);
        }
        simpoint_schedule_next_stop(count);
        return;
    }

    m = find_active_interval(count);

    if (m.should_trace) {
        fprintf(stderr,
            "SimPoint %d reached at %" PRIu64 " instructions"
            " (warmup: %" PRIu64 " simpoint start: %" PRIu64
            "). Enabling CF_LOG_INSTR\n",
            m.idx, count,
            g_array_index(adjusted_simpoints, uint64_t, m.idx),
            g_array_index(simpoints, uint64_t, m.idx));

        simpoint_set_mode(env, SIMPOINT_MODE_TRACING);
        simpoint_open_trace(env, m.idx, m.is_warmup);
        sp_state.in_warmup   = m.is_warmup;
        sp_state.current_idx = m.idx;

        global_loglevel_enable();
        cpu_loglevel_switch(env, QEMU_LOG_INSTR_LOGLEVEL_USER);

        tb_flush(env_cpu(env));
        cpu_loop_exit(env_cpu(env));
    }

    if (count > simpoint_end_of_last_interval()) {
        fprintf(stderr,
            "All simpoints complete at icount=%" PRIu64
            ", shutting down\n", count);
        sp_state.stop = true;
        simpoint_set_mode(env, SIMPOINT_MODE_INACTIVE);
        qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
        return;
    }

    /* Interval boundary between simpoints: report progress, keep going. */
    if (count % INTERVAL_SIZE == 0) {
        simpoint_progress("counting", count);
    }
    simpoint_schedule_next_stop(count);
}

/*
 * A TB exited with TB_EXIT_REQUESTED before executing anything. If that was
 * the inline countdown check (countdown < this TB's instruction count),
 * handle it:
 *  - more left in countdown_overflow: refill and retry the TB;
 *  - boundary falls inside this TB: retranslate it to end exactly at the
 *    boundary (same idea as icount's cflags_next_tb);
 *  - countdown is exactly zero: we are at the stop, handle it.
 */
bool qemu_simpoint_handle_countdown_exit(CPUState *cpu, TranslationBlock *tb)
{
    CPUArchState *env = cpu->env_ptr;
    int32_t countdown = qatomic_read(&qemu_simpoint_countdown);
    uint64_t remaining;

    if (!(tb_cflags(tb) & CF_SIMPOINT_COUNTDOWN) || !cpu_in_user_mode(env) ||
        !tb->simpoint_countdown ||
        (int64_t)countdown >= (int64_t)tb->simpoint_charge) {
        return false;
    }

    if (sp_state.mode != SIMPOINT_MODE_COUNTING || sp_state.paused) {
        /*
         * Stale counting TB reached through an old chain, or another
         * process used up the parked counter while ours is switched out
         * (filter=process): nothing to count, let it run.
         */
        qatomic_set(&qemu_simpoint_countdown, INT32_MAX);
        return true;
    }

    remaining = (uint64_t)countdown + sp_state.countdown_overflow;

    if (remaining >= tb->simpoint_charge) {
        simpoint_set_countdown(remaining);
        return true;
    }

    if (remaining > 0) {
        simpoint_set_countdown(remaining);
        cpu->cflags_next_tb = (tb_cflags(tb) & ~CF_COUNT_MASK) | remaining;
        return true;
    }

    simpoint_reached_stop(env);
    return true;
}

/*
 * A countdown TB charged its instructions to the countdown (and to its BBV
 * counter) at entry, but is being left at instruction @insn_idx, which did
 * not complete: a synchronous exception (page fault, CHERI fault, ...; the
 * instruction is retried or never runs) or a forced re-execution
 * (self-modifying code, watchpoint). Give back what was charged from that
 * instruction on, so COUNTING and the BBVs count retired instructions only,
 * as traced windows do. Without this, every mid-TB fault overcounted by the
 * rest of the TB, by amounts that depend on where TBs happen to start.
 */
void qemu_simpoint_unwind_tb(CPUState *cpu, TranslationBlock *tb,
                             int insn_idx)
{
    int n = (int)tb->simpoint_charge - insn_idx;

    if (n <= 0) {
        return;
    }
    qatomic_set(&qemu_simpoint_countdown,
                qatomic_read(&qemu_simpoint_countdown) + n);
    if (qemu_simpoint_bbv_mask && tb->simpoint_bbv_cell) {
        SimpointBBVCell *c = tb->simpoint_bbv_cell;

        if (c->weight >= (uint64_t)n) {
            c->weight -= n;
        }
    }
}




/*
 *  A printf that takes an array of argments unioned of all possible argument
 * types. Because we cant edit a VA_LIST, and we don't want the exponential blow
 * up of handling all combinations of types, we will bounce individual string
 * sections split in the fmt string to another buffer, then switch on all
 * possible types.
 */
static void g_string_append_printf_union_args(GString *string, const char *fmt,
                                              qemu_log_arg_t *args)
{

/* So Clang will not complain about the non-literal format. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#pragma GCC diagnostic ignored "-Wformat-security"

    char bounce_buf[256];

    size_t i = 0;
    bool format = false;
    char c;
    bool is_short, is_long, is_long_long;
    while ((c = bounce_buf[i++] = *fmt++)) {
        assert(i != sizeof(bounce_buf));
        if (!format) {
            /*
             * A safe amount under the maximum size. An (illegally) wrong format
             * will cause the assert to be hit, but is a bug on the caller's
             * part.
             */
            if (i >= (sizeof(bounce_buf) - 10)) {
                bounce_buf[i] = '\0';
                g_string_append_printf(string, bounce_buf);
                i = 0;
            }
            format = c == '%';
            is_short = is_long = is_long_long = false;
            continue;
        }
        bounce_buf[i] = '\0';
        switch (c) {
        case 'c':
            g_string_append_printf(string, bounce_buf, (args++)->charv);
            format = false;
            i = 0;
            break;
        case 'd':
        case 'i':
            if (is_long_long) {
                g_string_append_printf(string, bounce_buf, (args++)->longlongv);
            } else if (is_long) {
                g_string_append_printf(string, bounce_buf, (args++)->longv);
            } else if (is_short) {
                g_string_append_printf(string, bounce_buf, (args++)->shortv);
            } else {
                g_string_append_printf(string, bounce_buf, (args++)->intv);
            }
            format = false;
            i = 0;
            break;
        case 'u':
        case 'x':
        case 'X':
        case 'o':
            if (is_long_long) {
                g_string_append_printf(string, bounce_buf,
                                       (args++)->ulonglongv);
            } else if (is_long) {
                g_string_append_printf(string, bounce_buf, (args++)->ulongv);
            } else if (is_short) {
                g_string_append_printf(string, bounce_buf, (args++)->ushortv);
            } else {
                g_string_append_printf(string, bounce_buf, (args++)->uintv);
            }
            format = false;
            i = 0;
            break;
        case 'e':
        case 'E':
        case 'f':
        case 'g':
        case 'G':
            if (is_long) {
                g_string_append_printf(string, bounce_buf, (args++)->doublev);
            } else {
                g_string_append_printf(string, bounce_buf, (args++)->floatv);
            }
            format = false;
            i = 0;
            break;
        case 's':
        case 'p':
            g_string_append_printf(string, bounce_buf, (args++)->ptrv);
            format = false;
            i = 0;
            break;
        case '%':
            format = false;
            break;
        case 'h':
            is_short = true;
            break;
        case 'l':
            if (is_long) {
                is_long_long = true;
            }
            is_long = true;
            break;
        default:
            break;
        }
    }

    g_string_append_printf(string, bounce_buf);

#pragma clang diagnostic pop
}

static TCGv_i64 qemu_log_printf_valid_entries;

#define QEMU_PRINTF_LOG_OFFSET                                                 \
    ((offsetof(ArchCPU, parent_obj) - offsetof(ArchCPU, env)) +                \
     offsetof(struct CPUState, log_state.qemu_log_printf_buf))

void qemu_log_printf_create_globals(void)
{
    qemu_log_printf_valid_entries = tcg_global_mem_new_i64(
        cpu_env,
        QEMU_PRINTF_LOG_OFFSET + offsetof(qemu_log_printf_buf_t, valid_entries),
        "log_valids");
}

void qemu_log_gen_printf(DisasContextBase *base, const char *qemu_format,
                         const char *fmt, ...)
{

    if (!qemu_base_logging_enabled(base)) {
        return;
    }

    va_list args;
    va_start(args, fmt);

    size_t ndx = base->printf_used_ptr++;
    assert(
        ndx < QEMU_LOG_PRINTF_BUF_DEPTH &&
        "Increase QEMU_LOG_PRINTF_FLUSH_BARRIER or QEMU_LOG_PRINTF_BUF_DEPTH");

    size_t offset = QEMU_PRINTF_LOG_OFFSET +
                    (sizeof(qemu_log_arg_t) * (QEMU_LOG_PRINTF_ARG_MAX * ndx));

    int nargs = 0;
    char t;

    TCGv_i64 temp64 = tcg_temp_new_i64();
    TCGv_i32 temp32 = tcg_temp_new_i32();

    /* Store the format string out. */
    size_t fmt_offset = QEMU_PRINTF_LOG_OFFSET +
                        offsetof(qemu_log_printf_buf_t, fmts) +
                        (sizeof(const char *) * ndx);

#if UINTPTR_MAX == UINT32_MAX
    tcg_gen_movi_i32(temp32, (uintptr_t)fmt);
    tcg_gen_st_i32(temp32, cpu_env, fmt_offset);
#else
    tcg_gen_movi_i64(temp64, (uintptr_t)fmt);
    tcg_gen_st_i64(temp64, cpu_env, fmt_offset);
#endif

    /* Mark this entry as valid. */
    tcg_gen_movi_i64(temp64, (1ULL << ndx));
    tcg_gen_or_i64(qemu_log_printf_valid_entries, qemu_log_printf_valid_entries,
                   temp64);

    /*
     * Now process the qemu_format string and fmt string to generate tcg loads
     * and stores.
     */
    while ((t = *qemu_format++)) {
        assert(nargs != QEMU_LOG_PRINTF_ARG_MAX);
        /*
         * va_arg arguments are promoted according to standard promotion rules.
         * floats promote to doubles, types shorter than int promote to int.
         * Accessing va_arg with the wrong sign (but correct size) for
         * everything else is dancing with UB. The spec says its is OK if both
         * types could represent the value passed at runtime. However, as I am
         * only going to _store_ the value, I'm 99% certain I am still fine just
         * doing everything with one sign even when large magnitude values as
         * passed.
         */
        char c;
        bool format = false;
        bool is_short, is_long, is_long_long, is_signed;

        while ((c = *fmt++)) {
            if (!format) {
                format = c == '%';
                if (format) {
                    is_short = is_long = is_long_long = is_signed = false;
                }
                continue;
            }
            size_t arg_size = 0;
            uint64_t arg_const;
            switch (c) {
            case 'c':
                arg_size = sizeof(char);
                if (t == 'c') {
                    arg_const = (uint64_t)va_arg(args, int);
                }
                break;
            case 'd':
            case 'i':
                is_signed = true;
            case 'u':
            case 'x':
            case 'X':
            case 'o':
                if (is_long_long) {
                    arg_size = sizeof(long long);
                    if (t == 'c') {
                        arg_const = (uint64_t)va_arg(args, long long);
                    }
                } else if (is_long) {
                    arg_size = sizeof(long);
                    if (t == 'c') {
                        arg_const = (uint64_t)va_arg(args, long);
                    }
                } else if (is_short) {
                    arg_size = sizeof(short);
                    if (t == 'c') {
                        arg_const = (uint64_t)va_arg(args, int);
                    }
                } else {
                    arg_size = sizeof(int);
                    if (t == 'c') {
                        arg_const = (uint64_t)va_arg(args, int);
                    }
                }
                format = false;
                break;
            case 'e':
            case 'E':
            case 'f':
            case 'g':
            case 'G':
                if (is_long) {
                    if (t == 'c') {
                        arg_const = (uint64_t)va_arg(args, double);
                    }
                    arg_size = sizeof(double);
                } else {
                    if (t == 'c') {
                        arg_const = (uint64_t)(float)va_arg(args, double);
                    }
                    arg_size = sizeof(float);
                }
                format = false;
                break;
            case 's':
            case 'p':
                arg_size = sizeof(void *);
                /*
                 * This does not break strict aliasing as long as only void*
                 * and char* is passed.
                 */
                if (t == 'c') {
                    arg_const = (uint64_t)va_arg(args, void *);
                }
            case '%':
                format = false;
                break;
            case 'h':
                is_short = true;
                break;
            case 'l':
                if (is_long) {
                    is_long_long = true;
                }
                is_long = true;
                break;
            default:
                break;
            }
            if (arg_size != 0) {
                /* Use 32-bit ops. */
                if (arg_size <= 4) {
                    TCGv_i32 t32;
                    if (t == 'c') {
                        t32 = temp32;
                        tcg_gen_movi_i32(t32, (uint32_t)arg_const);
                    } else if (t == 'w') {
                        t32 = va_arg(args, TCGv_i32);
                    } else {
                        assert((t == 'd') && "bad QEMU format string");
                        t32 = temp32;
                        tcg_gen_extrl_i64_i32(t32, va_arg(args, TCGv_i64));
                    }
                    if (!t32) {
                        t32 = temp32;
                        tcg_gen_movi_i32(t32, 0);
                    }
                    switch (arg_size) {
                    case 1:
                        tcg_gen_st8_i32(t32, cpu_env, offset);
                        break;
                    case 2:
                        tcg_gen_st16_i32(t32, cpu_env, offset);
                        break;
                    case 4:
                        tcg_gen_st_i32(t32, cpu_env, offset);
                        break;
                    default:
                        g_assert_not_reached();
                    }
                } else {
                    assert(arg_size <= 8);
                    /* Use 64-bit ops. */
                    TCGv_i64 t64;
                    if (t == 'c') {
                        t64 = temp64;
                        tcg_gen_movi_i64(t64, arg_const);
                    } else if (t == 'w') {
                        t64 = temp64;
                        if (is_signed) {
                            tcg_gen_ext_i32_i64(t64, va_arg(args, TCGv_i32));
                        } else {
                            tcg_gen_extu_i32_i64(t64, va_arg(args, TCGv_i32));
                        }
                    } else {
                        assert((t == 'd') && "bad QEMU format string");
                        t64 = va_arg(args, TCGv_i64);
                    }
                    if (!t64) {
                        t64 = temp64;
                        tcg_gen_movi_i64(t64, 0);
                    }
                    tcg_gen_st_i64(t64, cpu_env, offset);
                }
                offset += sizeof(qemu_log_arg_t);
                break;
            }
        }
        assert(c != 0 && "Format strings do not match");
    }

    va_end(args);

    tcg_temp_free_i64(temp64);
    tcg_temp_free_i32(temp32);
}

void qemu_log_gen_printf_flush(DisasContextBase *base, bool flush_early,
                               bool force_flush)
{
    if (force_flush || ((base->printf_used_ptr != 0) &&
                        (flush_early || (base->printf_used_ptr >=
                                         (QEMU_LOG_PRINTF_FLUSH_BARRIER))))) {
        gen_helper_qemu_log_printf_dump(cpu_env);
        base->printf_used_ptr = 0;
    }
}

void qemu_log_instr_flush(CPUArchState *env)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);
    size_t curr = cpulog->ring_tail;
    cpu_log_instr_info_t *iinfo;

    if ((cpulog->flags & QEMU_LOG_INSTR_FLAG_BUFFERED) == 0)
        return;

    while (curr != cpulog->ring_head) {
        iinfo = &g_array_index(cpulog->instr_info, cpu_log_instr_info_t, curr);
        trace_format->emit_entry(env, iinfo);
        curr = (curr + 1) % cpulog->instr_info->len;
    }
    cpulog->ring_tail = cpulog->ring_head;
}

/* Instruction logging helpers */

/* Dump out all the accumalated printf's */
void helper_qemu_log_printf_dump(CPUArchState *env)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);

    tcg_debug_assert((QEMU_PRINTF_LOG_OFFSET + ((uintptr_t)env)) ==
                     (uintptr_t)(&cpulog->qemu_log_printf_buf));

    uint64_t valid = cpulog->qemu_log_printf_buf.valid_entries;
    cpulog->qemu_log_printf_buf.valid_entries = 0;

    if (!qemu_log_instr_enabled(env)) {
        return;
    }

    cpu_log_instr_info_t *iinfo = get_cpu_log_instr_info(env);

    while (valid) {
        size_t ndx = ctz64(valid);
        valid ^= (1 << ndx);
        qemu_log_arg_t *args =
            cpulog->qemu_log_printf_buf.args +
            (ndx * QEMU_LOG_PRINTF_ARG_MAX);
        const char *fmt = cpulog->qemu_log_printf_buf.fmts[ndx];
        g_string_append_printf_union_args(iinfo->txt_buffer, fmt, args);
    }
}

/*
 * Enable or disable buffered logging that is triggered by the target
 * via qemu_log_instr_flush().
 */
void helper_qemu_log_instr_buffered_mode(CPUArchState *env, uint32_t enable)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);

    if (enable) {
        cpulog->flags |= QEMU_LOG_INSTR_FLAG_BUFFERED;
    } else {
        cpulog->flags &= ~QEMU_LOG_INSTR_FLAG_BUFFERED;
    }
}

/* Helper version of qemu_log_instr_flush */
void helper_qemu_log_instr_buffer_flush(CPUArchState *env)
{
    qemu_log_instr_flush(env);
}

/* Start logging all instructions on the current CPU */
/*
 * The generic qtrace start/stop instructions (slti zero, zero, 0x1b/0x1e/
 * 0x2b/0x2e) are not meant for SimPoint runs, which use 0x3b/0x3e. With
 * hw.qemu_trace_perthread=1 the CheriBSD kernel issues them on every
 * context switch; acting on them would turn logging off in the middle of a
 * window (freezing it, since nothing is counted) or on during counting.
 */
static bool simpoint_ignores_qtrace_magic(void)
{
    static bool warned;

    if ((!simpoints && !simpoint_pcs) ||
        sp_state.mode == SIMPOINT_MODE_INACTIVE) {
        return false;
    }
    if (!warned) {
        warned = true;
        fprintf(stderr, "[simpoint] ignoring qtrace start/stop instructions "
                "during the SimPoint run (the kernel issues them on context "
                "switches when hw.qemu_trace_perthread=1; set it to 0, and "
                "use -simpoints filter=process to exclude other "
                "processes)\n");
    }
    return true;
}

void helper_qemu_log_instr_start(CPUArchState *env, target_ulong pc)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);

    if (simpoint_ignores_qtrace_magic()) {
        return;
    }

    log_assert(cpulog != NULL && "Invalid log state");
    global_loglevel_enable();

    /* If we are already started in the correct mode, bail */
    if (cpulog->loglevel == QEMU_LOG_INSTR_LOGLEVEL_ALL &&
        cpulog->loglevel_active)
        return;

    cpu_loglevel_switch(env, QEMU_LOG_INSTR_LOGLEVEL_ALL);
}

/* Start logging user-only instructions on the current CPU */
void helper_qemu_log_instr_user_start(CPUArchState *env, target_ulong pc)
{
    cpu_log_instr_state_t *cpulog = get_cpu_log_state(env);

    if (simpoint_ignores_qtrace_magic()) {
        return;
    }

    log_assert(cpulog != NULL && "Invalid log state");
    global_loglevel_enable();

    /* If we are already in the correct mode, bail */
    if (cpulog->loglevel == QEMU_LOG_INSTR_LOGLEVEL_USER)
        return;

    cpu_loglevel_switch(env, QEMU_LOG_INSTR_LOGLEVEL_USER);
}

/* Stop logging on the current CPU */
void helper_qemu_log_instr_stop(CPUArchState *env, target_ulong pc)
{
    if (simpoint_ignores_qtrace_magic()) {
        return;
    }

    cpu_loglevel_switch(env, QEMU_LOG_INSTR_LOGLEVEL_NONE);
}


/* Start logging user-only instructions on the current CPU if SimPoint region is hit*/
void helper_qemu_log_instr_simpoint_start(CPUArchState *env, target_ulong pc)
{
    if (sp_state.mode != SIMPOINT_MODE_INACTIVE) {
        fprintf(stderr, "simpoint_start: already active (mode=%d), ignoring\n",
                sp_state.mode);
        return;
    }

    if (!simpoints && !simpoint_pcs) {
        fprintf(stderr, "helper_qemu_log_instr_simpoint_start(): no simpoints configured!\n"
            "Terminating QEMU.\n"
            "Usage:"
            "-simpoints file=PATH/TO/SIMPOINTS,interval=<INSTRUCTIONS TO TRACE>"
            "start_pc=<Address to begin tracing logic in hex>\n");
            qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
        return;
    }

    /*
     * sp_state, the countdown and the BBV counters are global and updated
     * without locking from whichever vCPU runs: one vCPU only.
     */
    {
        CPUState *c;
        int ncpus = 0;

        CPU_FOREACH(c) {
            ncpus++;
        }
        if (ncpus != 1) {
            fprintf(stderr, "helper_qemu_log_instr_simpoint_start(): SimPoint "
                    "runs need exactly one vCPU (-smp 1), have %d.\n"
                    "Terminating QEMU.\n", ncpus);
            qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);
            return;
        }
    }

    fprintf(stderr, "Simpoint-aware tracing started (START_PC=0x%" PRIx64 ")\n", START_PC);

    sp_state.instr_count = 0;
    sp_state.current_idx = -1;
    sp_state.in_warmup   = false;
    sp_state.stop        = false;
    sp_state.file_open   = false;
    sp_state.program_root = 0;
    sp_state.paused      = false;

    if (simpoint_bbv_mode()) {
        simpoint_bbv_open();
    }


    if (START_PC != 0) {
        simpoint_set_mode(env, SIMPOINT_MODE_WAIT_START_PC);
    } else {
        simpoint_set_mode(env, SIMPOINT_MODE_COUNTING);
    } 


    cpu_loglevel_switch(env, QEMU_LOG_INSTR_LOGLEVEL_NONE);

    /* Flushing forces TBs to recompile
    *  The flag that determines whether or not we log is baked into the TBs,
    *  so flushing dynamically sets or clears that bit
    */ 
    tb_flush(env_cpu(env)); 

}

/* Stop logging on the current CPU if we're outside the simpoint region*/
void helper_qemu_log_instr_simpoint_stop(CPUArchState *env, target_ulong pc)
{
    bool was_tracing = sp_state.mode == SIMPOINT_MODE_TRACING;

    /* Leaving COUNTING mode syncs instr_count from the inline countdown. */
    simpoint_set_mode(env, SIMPOINT_MODE_INACTIVE);
    sp_state.paused = false;
    sp_state.program_root = 0;
    if (simpoint_bbv_mode()) {
        simpoint_bbv_close();
    }

    fprintf(stderr, "Simpoint-aware tracing stopped (counted %" PRIu64 " instructions)\n",
            sp_state.instr_count);

    /* If we were in tracing mode, clean up */
    if (was_tracing)
        simpoint_close_trace();

    /* Disable CF_LOG_INSTR if it was on */
    cpu_loglevel_switch(env, QEMU_LOG_INSTR_LOGLEVEL_NONE);
}

/* Start logging all instructions on all CPUs */
void helper_qemu_log_instr_allcpu_start(void)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        helper_qemu_log_instr_start(cpu->env_ptr, 0);
    }
}

/* Start logging user-only instructions on all CPUs */
void helper_qemu_log_instr_allcpu_user_start(void)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        helper_qemu_log_instr_user_start(cpu->env_ptr, 0);
    }
}

/* Stop logging instructions on all CPUs */
void helper_qemu_log_instr_allcpu_stop(void)
{
    CPUState *cpu;

    CPU_FOREACH(cpu) {
        helper_qemu_log_instr_stop(cpu->env_ptr, 0);
    }
}

void helper_qemu_log_instr_commit(CPUArchState *env)
{
    qemu_log_instr_commit(env);
}

void helper_qemu_log_instr_load64(CPUArchState *env, target_ulong addr,
                                  uint64_t value, TCGMemOpIdx oi)
{
    if (qemu_log_instr_enabled(env))
        qemu_log_instr_mem_int(env, addr, LMI_LD, oi, value);
}

void helper_qemu_log_instr_store64(CPUArchState *env, target_ulong addr,
                                   uint64_t value, TCGMemOpIdx oi)
{
    if (qemu_log_instr_enabled(env))
        qemu_log_instr_mem_int(env, addr, LMI_ST, oi, value);
}

void helper_qemu_log_instr_load32(CPUArchState *env, target_ulong addr,
                                  uint32_t value, TCGMemOpIdx oi)
{
    if (qemu_log_instr_enabled(env))
        qemu_log_instr_mem_int(env, addr, LMI_LD, oi, (uint64_t)value);
}

void helper_qemu_log_instr_store32(CPUArchState *env, target_ulong addr,
                                   uint32_t value, TCGMemOpIdx oi)
{
    if (qemu_log_instr_enabled(env))
        qemu_log_instr_mem_int(env, addr, LMI_ST, oi, (uint64_t)value);
}

void helper_log_value(CPUArchState *env, const void* ptr, uint64_t value)
{
    qemu_maybe_log_instr_extra(env, "%s: " TARGET_FMT_plx "\n", ptr, value);
}

static void emit_nop_start(CPUArchState *env, target_ulong pc) {}
static void emit_nop_stop(CPUArchState *env, target_ulong pc) {}
static void emit_nop_entry(CPUArchState *env, cpu_log_instr_info_t *iinfo) {}

/*
 * Hooks for each trace format
 */
static trace_fmt_hooks_t trace_formats[] = {
    {
        .emit_header = NULL,
        .emit_start = emit_text_start,
        .emit_stop = emit_text_stop,
        .emit_entry = emit_text_entry
    },
    {
        .emit_header = emit_cvtrace_header,
        .emit_start = emit_cvtrace_start,
        .emit_stop = emit_cvtrace_stop,
        .emit_entry = emit_cvtrace_entry
    },
    {
        .emit_header = NULL,
        .emit_start = emit_nop_start,
        .emit_stop = emit_nop_stop,
        .emit_entry = emit_nop_entry
    },
    {   //charles
        .emit_header = NULL,
        .emit_start = emit_champsim_start,
        .emit_stop = emit_champsim_stop,
        .emit_entry = emit_champsim_entry
    },
    {   //charles
        .emit_header = NULL,
        .emit_start = emit_champsim_cheri_start,
        .emit_stop = emit_champsim_cheri_stop,
        .emit_entry = emit_champsim_cheri_entry
    }
};

#endif /* CONFIG_TCG_LOG_INSTR */
