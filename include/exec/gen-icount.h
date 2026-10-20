#ifndef GEN_ICOUNT_H
#define GEN_ICOUNT_H

#include "qemu/timer.h"

/* Helpers for instruction counting code generation.  */

static TCGOp *icount_start_insn;

static inline void gen_io_start(void)
{
    TCGv_i32 tmp = tcg_const_i32(1);
    tcg_gen_st_i32(tmp, cpu_env,
                   offsetof(ArchCPU, parent_obj.can_do_io) -
                   offsetof(ArchCPU, env));
    tcg_temp_free_i32(tmp);
}

/*
 * cpu->can_do_io is cleared automatically at the beginning of
 * each translation block.  The cost is minimal and only paid
 * for -icount, plus it would be very easy to forget doing it
 * in the translator.  Therefore, backends only need to call
 * gen_io_start.
 */
static inline void gen_io_end(void)
{
    TCGv_i32 tmp = tcg_const_i32(0);
    tcg_gen_st_i32(tmp, cpu_env,
                   offsetof(ArchCPU, parent_obj.can_do_io) -
                   offsetof(ArchCPU, env));
    tcg_temp_free_i32(tmp);
}

#ifdef CONFIG_TCG_LOG_INSTR
/* SimPoint COUNTING countdown, see include/exec/log_instr.h */
#ifndef QEMU_SIMPOINT_COUNTDOWN_DECLARED
#define QEMU_SIMPOINT_COUNTDOWN_DECLARED
extern int32_t qemu_simpoint_countdown;
#endif
static TCGOp *simpoint_countdown_sub_op;

/*
 * Built-in BBV collection (-simpoints bbv=FILE): every counting TB adds its
 * instruction count to its block's counter, masked by qemu_simpoint_bbv_mask
 * (all ones while counting our program, 0 while it is switched out), so
 * nothing calls out of generated code. The immediate is patched in
 * gen_tb_end like the countdown's.
 */
extern uint64_t qemu_simpoint_bbv_mask;
#ifndef QEMU_SIMPOINT_BBV_COUNTER_DECLARED
#define QEMU_SIMPOINT_BBV_COUNTER_DECLARED
uint64_t *qemu_simpoint_bbv_counter(uint64_t pc);
#endif
static TCGOp *simpoint_bbv_and_op;

#if UINTPTR_MAX == UINT32_MAX
# define simpoint_countdown_ptr() \
    ((TCGv_ptr)tcg_constant_i32((intptr_t)&qemu_simpoint_countdown))
#else
# define simpoint_countdown_ptr() \
    ((TCGv_ptr)tcg_constant_i64((intptr_t)&qemu_simpoint_countdown))
#endif
#endif

/*
 * @emit_countdown: emit the SimPoint COUNTING countdown check. Like icount,
 * the TB's instruction count is subtracted up front (the immediate is
 * patched in gen_tb_end) and the TB exits with TB_EXIT_REQUESTED before
 * executing anything if the countdown would go negative. Both checks run
 * before either counter is stored, so an exit never counts a TB that
 * did not execute. Direct and indirect TB chaining are unaffected.
 */
static inline void gen_tb_start_simpoint(const TranslationBlock *tb,
                                         bool emit_countdown)
{
    TCGv_i32 count;
#ifdef CONFIG_TCG_LOG_INSTR
    TCGv_i32 countdown = NULL;
#else
    tcg_debug_assert(!emit_countdown);
#endif

    tcg_ctx->exitreq_label = gen_new_label();
    if (tb_cflags(tb) & CF_USE_ICOUNT) {
        count = tcg_temp_local_new_i32();
    } else {
        count = tcg_temp_new_i32();
    }

    tcg_gen_ld_i32(count, cpu_env,
                   offsetof(ArchCPU, neg.icount_decr.u32) -
                   offsetof(ArchCPU, env));

    if (tb_cflags(tb) & CF_USE_ICOUNT) {
        /*
         * We emit a sub with a dummy immediate argument. Keep the insn index
         * of the sub so that we later (when we know the actual insn count)
         * can update the argument with the actual insn count.
         */
        tcg_gen_sub_i32(count, count, tcg_constant_i32(0));
        icount_start_insn = tcg_last_op();
    }

    tcg_gen_brcondi_i32(TCG_COND_LT, count, 0, tcg_ctx->exitreq_label);

#ifdef CONFIG_TCG_LOG_INSTR
    if (emit_countdown) {
        /* Local temp: the value is stored after the branch below. */
        countdown = tcg_temp_local_new_i32();
        tcg_gen_ld_i32(countdown, simpoint_countdown_ptr(), 0);
        tcg_gen_sub_i32(countdown, countdown, tcg_constant_i32(0));
        simpoint_countdown_sub_op = tcg_last_op();
        tcg_gen_brcondi_i32(TCG_COND_LT, countdown, 0,
                            tcg_ctx->exitreq_label);
    } else {
        simpoint_countdown_sub_op = NULL;
    }
#endif

    if (tb_cflags(tb) & CF_USE_ICOUNT) {
        tcg_gen_st16_i32(count, cpu_env,
                         offsetof(ArchCPU, neg.icount_decr.u16.low) -
                         offsetof(ArchCPU, env));
        gen_io_end();
    }

#ifdef CONFIG_TCG_LOG_INSTR
    if (emit_countdown) {
        tcg_gen_st_i32(countdown, simpoint_countdown_ptr(), 0);
        tcg_temp_free_i32(countdown);
    }
    simpoint_bbv_and_op = NULL;
#if TCG_TARGET_REG_BITS == 64
    if (emit_countdown) {
        uint64_t *ctr = qemu_simpoint_bbv_counter(tb->pc);

        if (ctr) {
            TCGv_i64 inc = tcg_temp_new_i64();
            TCGv_i64 val = tcg_temp_new_i64();
            TCGv_ptr mask_p = (TCGv_ptr)tcg_constant_i64(
                (intptr_t)&qemu_simpoint_bbv_mask);
            TCGv_ptr ctr_p = (TCGv_ptr)tcg_constant_i64((intptr_t)ctr);

            tcg_gen_ld_i64(inc, mask_p, 0);
            tcg_gen_and_i64(inc, inc, tcg_constant_i64(0));
            simpoint_bbv_and_op = tcg_last_op();
            tcg_gen_ld_i64(val, ctr_p, 0);
            tcg_gen_add_i64(val, val, inc);
            tcg_gen_st_i64(val, ctr_p, 0);
            tcg_temp_free_i64(inc);
            tcg_temp_free_i64(val);
        }
    }
#endif
#endif

    tcg_temp_free_i32(count);
}

static inline void gen_tb_start(const TranslationBlock *tb)
{
    gen_tb_start_simpoint(tb, false);
}

/*
 * @charge: what the SimPoint countdown and BBV add charge (the instructions
 * that can retire; less than @num_insns when the TB ends in an exception the
 * translator raises unconditionally). icount keeps using @num_insns.
 */
static inline void gen_tb_end_charge(const TranslationBlock *tb, int num_insns,
                                     int charge)
{
    if (tb_cflags(tb) & CF_USE_ICOUNT) {
        /*
         * Update the num_insn immediate parameter now that we know
         * the actual insn count.
         */
        tcg_set_insn_param(icount_start_insn, 2,
                           tcgv_i32_arg(tcg_constant_i32(num_insns)));
    }
#ifdef CONFIG_TCG_LOG_INSTR
    if (simpoint_countdown_sub_op) {
        tcg_set_insn_param(simpoint_countdown_sub_op, 2,
                           tcgv_i32_arg(tcg_constant_i32(charge)));
        simpoint_countdown_sub_op = NULL;
    }
#if TCG_TARGET_REG_BITS == 64
    if (simpoint_bbv_and_op) {
        tcg_set_insn_param(simpoint_bbv_and_op, 2,
                           tcgv_i64_arg(tcg_constant_i64(charge)));
        simpoint_bbv_and_op = NULL;
    }
#endif
#endif

    gen_set_label(tcg_ctx->exitreq_label);
    tcg_gen_exit_tb(tb, TB_EXIT_REQUESTED);
}

static inline void gen_tb_end(const TranslationBlock *tb, int num_insns)
{
    gen_tb_end_charge(tb, num_insns, num_insns);
}

#endif
