#include <dirent.h>
#include <limits.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char *ios_shim_mkdtemp(char *tmpl) {
    const char *tmpdir = getenv("TMPDIR");
    if (tmpdir && strncmp(tmpl, "/tmp/", 5) == 0) {
        const char *base = tmpl + 5;
        char buf[PATH_MAX];
        int n = snprintf(buf, sizeof(buf), "%s%s%s",
                         tmpdir,
                         (tmpdir[strlen(tmpdir) - 1] == '/') ? "" : "/",
                         base);
        if (n > 0 && (size_t)n < PATH_MAX) {
            memcpy(tmpl, buf, (size_t)n + 1);
        }
    }
    return mkdtemp(tmpl);
}

static int ios_rm_rf(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0)
        return 0;
    if (S_ISDIR(st.st_mode)) {
        DIR *d = opendir(path);
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL) {
                if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
                    continue;
                char child[4096];
                snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
                ios_rm_rf(child);
            }
            closedir(d);
        }
        return rmdir(path);
    }
    return unlink(path);
}

static int ios_shim_system(const char *cmd) {
    if (strncmp(cmd, "rm -rf ", 7) != 0)
        return -1;
    const char *start = strchr(cmd, '\'');
    const char *end = start ? strrchr(start + 1, '\'') : NULL;
    if (start && end && end > start + 1) {
        size_t len = (size_t)(end - (start + 1));
        char path[4096];
        if (len < sizeof(path)) {
            memcpy(path, start + 1, len);
            path[len] = '\0';
            return ios_rm_rf(path);
        }
    }
    return -1;
}

static jmp_buf g_sbm_exit_jmp;
static int g_sbm_exit_code = 0;
static int g_in_ios_run = 0;

#define mkdtemp(tmpl) ios_shim_mkdtemp(tmpl)
#define system(cmd) ios_shim_system(cmd)
#define main sbm_api_test_main
#define _exit(code) \
    do { \
        g_sbm_exit_code = (code); \
        longjmp(g_sbm_exit_jmp, 1); \
    } while (0)

#include "tests/integration/sbm_api_test.c"

#undef _exit
#undef main
#undef system
#undef mkdtemp

int run_sbm_api_suite(const char *rootfs_path) {
    char *argv[] = { "sbm_api_test", (char *)rootfs_path, NULL };
    if (setjmp(g_sbm_exit_jmp) != 0)
        return g_sbm_exit_code;
    return sbm_api_test_main(2, argv);
}

int ios_boot_rootfs(const char *rootfs_path) {
    return boot(rootfs_path);
}

int ios_run_guest_cmd(const char *cmd, char *out, size_t out_size, int timeout_ms) {
    g_in_ios_run = 1;
    if (setjmp(g_sbm_exit_jmp) != 0) {
        g_in_ios_run = 0;
        if (session.pid > 0)
            iul_kill_process_group(session.pid, SIGKILL_);
        close_session();
        return -1;
    }
    int rc = run(cmd, out, out_size, timeout_ms);
    g_in_ios_run = 0;
    return rc;
}

void ios_cleanup_devfs(void) {
    if (!g_in_ios_run)
        remove_devfs();
}
