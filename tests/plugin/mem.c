/*
 * Copyright (C) 2018, Emilio G. Cota <cota@braap.org>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>
#include <sys/wait.h>
#include <errno.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

static uint64_t inline_mem_count;
static uint64_t cb_mem_count;
static uint64_t io_count;
static bool do_inline, do_callback;
static bool do_haddr;
static bool do_text;
static bool do_xz;
static gchar *out_path;
static FILE *out_fp;
static enum qemu_plugin_mem_rw rw = QEMU_PLUGIN_MEM_RW;

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    g_autoptr(GString) out = g_string_new("");
    int status = 0;
    g_autoptr(GError) err = NULL;

    if (do_inline) {
        g_string_printf(out, "inline mem accesses: %" PRIu64 "\n", inline_mem_count);
    }
    if (do_callback) {
        g_string_append_printf(out, "callback mem accesses: %" PRIu64 "\n", cb_mem_count);
    }
    if (do_haddr) {
        g_string_append_printf(out, "io accesses: %" PRIu64 "\n", io_count);
    }
    qemu_plugin_outs(out->str);

    if (out_fp) {
        if (fflush(out_fp) != 0 || fclose(out_fp) != 0) {
            g_autofree gchar *msg = g_strdup_printf("failed to flush/close output '%s': %s\n",
                                                    out_path ? out_path : "(null)",
                                                    g_strerror(errno));
            qemu_plugin_outs(msg);
        }
        out_fp = NULL;
    }
    if (do_xz && out_path) {
        const gchar *argv[] = { "xz", "-f", "-z", out_path, NULL };
        if (!g_spawn_sync(NULL, (gchar **)argv, NULL, G_SPAWN_SEARCH_PATH,
                          NULL, NULL, NULL, NULL, &status, &err)) {
            g_autofree gchar *msg = g_strdup_printf("xz compression failed: %s\n",
                                                    err ? err->message : "unknown");
            qemu_plugin_outs(msg);
        } else if (status != 0) {
            g_autofree gchar *msg = g_strdup_printf("xz exited with status %d\n",
                                                    WEXITSTATUS(status));
            qemu_plugin_outs(msg);
        }
    }
    g_free(out_path);
    out_path = NULL;
}

static void vcpu_mem(unsigned int cpu_index, qemu_plugin_meminfo_t meminfo,
                     uint64_t vaddr, void *udata)
{
    struct qemu_plugin_cheri_auth auth;

    if (do_haddr) {
        struct qemu_plugin_hwaddr *hwaddr;
        hwaddr = qemu_plugin_get_hwaddr(meminfo, vaddr);
        if (qemu_plugin_hwaddr_is_io(hwaddr)) {
            io_count++;
        } else {
            cb_mem_count++;
        }
    } else {
        cb_mem_count++;
    }

    if (do_text && out_fp) {
        fprintf(out_fp, "cpu=%u %c vaddr=0x%" PRIx64 " size=%u",
                cpu_index, qemu_plugin_mem_is_store(meminfo) ? 'W' : 'R',
                vaddr, 1u << qemu_plugin_mem_size_shift(meminfo));
        if (qemu_plugin_mem_get_cheri_auth(meminfo, &auth)) {
            fprintf(out_fp,
                    " auth_src=%s%u auth_tag=%u auth_perms=0x%x auth_base=0x%" PRIx64
                    " auth_len=0x%" PRIx64 " auth_off=0x%" PRIx64,
                    auth.is_ddc ? "DDC" : "c", auth.regnum, auth.tag,
                    auth.perms, auth.base, auth.length, auth.offset);
        }
        fputc('\n', out_fp);
    }
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n = qemu_plugin_tb_n_insns(tb);
    size_t i;

    for (i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);

        if (do_inline) {
            qemu_plugin_register_vcpu_mem_inline(insn, rw,
                                                 QEMU_PLUGIN_INLINE_ADD_U64,
                                                 &inline_mem_count, 1);
        }
        if (do_callback) {
            qemu_plugin_register_vcpu_mem_cb(insn, vcpu_mem,
                                             QEMU_PLUGIN_CB_NO_REGS,
                                             rw, NULL);
        }
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    for (int i = 0; i < argc; i++) {
        const char *arg = argv[i];
        if (!strcmp(arg, "haddr")) {
            do_haddr = true;
        } else if (!strcmp(arg, "text")) {
            do_text = true;
        } else if (!strcmp(arg, "xz")) {
            do_xz = true;
        } else if (!strncmp(arg, "out=", 4)) {
            g_free(out_path);
            out_path = g_strdup(arg + 4);
        } else if (i == 1) {
            if (!strcmp(arg, "r")) {
                rw = QEMU_PLUGIN_MEM_R;
            } else if (!strcmp(arg, "w")) {
                rw = QEMU_PLUGIN_MEM_W;
            }
        }
    }

    if (argc && !strcmp(argv[0], "inline")) {
        do_inline = true;
        do_callback = false;
    } else if (argc && !strcmp(argv[0], "both")) {
        do_inline = true;
        do_callback = true;
    } else {
        do_callback = true;
    }

    if (do_text && out_path) {
        out_fp = fopen(out_path, "w");
        if (!out_fp) {
            g_autofree gchar *msg = g_strdup_printf("failed to open output '%s': %s\n",
                                                    out_path, g_strerror(errno));
            qemu_plugin_outs(msg);
            return -1;
        }
    }

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    return 0;
}
