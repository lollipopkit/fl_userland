#include "untar.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

static unsigned long long parse_octal(const char *p, size_t n) {
    unsigned long long v = 0;
    size_t i = 0;
    while (i < n && (p[i] == ' ' || p[i] == '\0'))
        i++;
    while (i < n && p[i] >= '0' && p[i] <= '7') {
        v = (v << 3) | (unsigned long long)(p[i] - '0');
        i++;
    }
    return v;
}

static int mkdir_p(const char *path, mode_t mode) {
    char tmp[PATH_MAX];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(tmp))
        return -1;
    memcpy(tmp, path, len + 1);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, mode) != 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, mode) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int ensure_parent_dir(const char *full_path) {
    char parent[PATH_MAX];
    const char *slash = strrchr(full_path, '/');
    if (!slash)
        return 0;
    size_t len = (size_t)(slash - full_path);
    if (len == 0)
        return 0;
    if (len >= sizeof(parent))
        return -1;
    memcpy(parent, full_path, len);
    parent[len] = '\0';
    return mkdir_p(parent, 0755);
}

static int gzread_exact(gzFile gz, void *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int n = gzread(gz, (char *)buf + off, (unsigned)(len - off));
        if (n <= 0)
            return -1;
        off += (size_t)n;
    }
    return 0;
}

int untar_gz(const char *tgz_path, const char *dest_dir) {
    gzFile gz = gzopen(tgz_path, "rb");
    if (!gz) {
        fprintf(stderr, "untar_gz: gzopen(%s) failed\n", tgz_path);
        return -1;
    }

    char pax_path[PATH_MAX];
    char pax_link[PATH_MAX];
    pax_path[0] = '\0';
    pax_link[0] = '\0';

    unsigned char hdr[512];
    int zero_blocks = 0;
    int rc = 0;

    while (1) {
        int n = gzread(gz, hdr, sizeof(hdr));
        if (n == 0)
            break;
        if (n != sizeof(hdr)) {
            fprintf(stderr, "untar_gz: short header read (%d)\n", n);
            rc = -1;
            break;
        }

        int all_zero = 1;
        for (size_t i = 0; i < sizeof(hdr); i++) {
            if (hdr[i] != 0) {
                all_zero = 0;
                break;
            }
        }
        if (all_zero) {
            if (++zero_blocks >= 2)
                break;
            continue;
        }
        zero_blocks = 0;

        char name[PATH_MAX];
        if (pax_path[0] != '\0') {
            snprintf(name, sizeof(name), "%s", pax_path);
            pax_path[0] = '\0';
        } else {
            char raw_name[101], prefix[156];
            memcpy(raw_name, hdr + 0, 100);
            raw_name[100] = '\0';
            memcpy(prefix, hdr + 345, 155);
            prefix[155] = '\0';
            if (prefix[0] != '\0')
                snprintf(name, sizeof(name), "%s/%s", prefix, raw_name);
            else
                snprintf(name, sizeof(name), "%s", raw_name);
        }

        char linkname[PATH_MAX];
        if (pax_link[0] != '\0') {
            snprintf(linkname, sizeof(linkname), "%s", pax_link);
            pax_link[0] = '\0';
        } else {
            memcpy(linkname, hdr + 157, 100);
            linkname[100] = '\0';
        }

        unsigned long long mode = parse_octal((const char *)(hdr + 100), 8);
        unsigned long long size = parse_octal((const char *)(hdr + 124), 12);
        char typeflag = (char)hdr[156];
        if (typeflag == '\0')
            typeflag = '0';

        // Strip leading "./" or "/".
        const char *rel = name;
        while (rel[0] == '.' && rel[1] == '/')
            rel += 2;
        while (rel[0] == '/')
            rel++;

        size_t padded = ((size_t)size + 511) & ~(size_t)511;

        if (typeflag == 'L' || typeflag == 'K') {
            if (size >= PATH_MAX) {
                rc = -1;
                break;
            }
            char *dst = (typeflag == 'L') ? pax_path : pax_link;
            if (gzread_exact(gz, dst, (size_t)size) != 0) {
                rc = -1;
                break;
            }
            dst[size] = '\0';
            if (padded > size) {
                char pad[512];
                if (gzread_exact(gz, pad, padded - (size_t)size) != 0) {
                    rc = -1;
                    break;
                }
            }
            continue;
        }

        if (typeflag == 'x') {
            if (size >= 65536) {
                rc = -1;
                break;
            }
            char *buf = malloc((size_t)size + 1);
            if (!buf) {
                rc = -1;
                break;
            }
            if (gzread_exact(gz, buf, (size_t)size) != 0) {
                free(buf);
                rc = -1;
                break;
            }
            buf[size] = '\0';
            size_t pos = 0;
            while (pos < (size_t)size) {
                char *sp = memchr(buf + pos, ' ', (size_t)size - pos);
                if (!sp)
                    break;
                unsigned long rec_len = strtoul(buf + pos, NULL, 10);
                if (rec_len == 0 || pos + rec_len > (size_t)size)
                    break;
                size_t kv_start = (size_t)(sp - buf) + 1;
                size_t kv_end = pos + rec_len;
                if (kv_end > kv_start && buf[kv_end - 1] == '\n')
                    kv_end--;
                buf[kv_end] = '\0';
                if (strncmp(buf + kv_start, "path=", 5) == 0) {
                    snprintf(pax_path, sizeof(pax_path), "%s", buf + kv_start + 5);
                } else if (strncmp(buf + kv_start, "linkpath=", 9) == 0) {
                    snprintf(pax_link, sizeof(pax_link), "%s", buf + kv_start + 9);
                }
                pos += rec_len;
            }
            free(buf);
            if (padded > size) {
                char pad[512];
                if (gzread_exact(gz, pad, padded - (size_t)size) != 0) {
                    rc = -1;
                    break;
                }
            }
            continue;
        }

        if (typeflag == 'g') {
            // Skip global PAX extended header payload.
            size_t rem = padded;
            char skip[512];
            while (rem > 0) {
                size_t chunk = rem > sizeof(skip) ? sizeof(skip) : rem;
                if (gzread_exact(gz, skip, chunk) != 0) {
                    rc = -1;
                    break;
                }
                rem -= chunk;
            }
            if (rc != 0)
                break;
            continue;
        }

        char full[PATH_MAX];
        if (rel[0] == '\0' || strcmp(rel, ".") == 0) {
            snprintf(full, sizeof(full), "%s", dest_dir);
        } else {
            snprintf(full, sizeof(full), "%s/%s", dest_dir, rel);
        }

        if (typeflag == '5') {
            if (mkdir_p(full, (mode_t)((mode & 0777) | 0700)) != 0) {
                fprintf(stderr, "untar_gz: mkdir_p(%s) failed: %s\n", full, strerror(errno));
                rc = -1;
                break;
            }
        } else if (typeflag == '2') {
            if (ensure_parent_dir(full) != 0) {
                rc = -1;
                break;
            }
            unlink(full);
            if (symlink(linkname, full) != 0) {
                fprintf(stderr, "untar_gz: symlink(%s -> %s) failed: %s\n", full, linkname, strerror(errno));
                rc = -1;
                break;
            }
        } else if (typeflag == '1') {
            const char *lrel = linkname;
            while (lrel[0] == '.' && lrel[1] == '/')
                lrel += 2;
            while (lrel[0] == '/')
                lrel++;
            char target[PATH_MAX];
            snprintf(target, sizeof(target), "%s/%s", dest_dir, lrel);
            if (ensure_parent_dir(full) != 0) {
                rc = -1;
                break;
            }
            unlink(full);
            if (link(target, full) != 0) {
                fprintf(stderr, "untar_gz: link(%s -> %s) failed: %s\n", full, target, strerror(errno));
                rc = -1;
                break;
            }
        } else if (typeflag == '0') {
            if (ensure_parent_dir(full) != 0) {
                rc = -1;
                break;
            }
            unlink(full);
            int fd = open(full, O_WRONLY | O_CREAT | O_TRUNC, (mode_t)((mode & 0777) | 0600));
            if (fd < 0) {
                fprintf(stderr, "untar_gz: open(%s) failed: %s\n", full, strerror(errno));
                rc = -1;
                break;
            }
            size_t rem = (size_t)size;
            char buf[4096];
            while (rem > 0) {
                size_t chunk = rem > sizeof(buf) ? sizeof(buf) : rem;
                if (gzread_exact(gz, buf, chunk) != 0) {
                    rc = -1;
                    break;
                }
                size_t woff = 0;
                while (woff < chunk) {
                    ssize_t w = write(fd, buf + woff, chunk - woff);
                    if (w <= 0) {
                        rc = -1;
                        break;
                    }
                    woff += (size_t)w;
                }
                if (rc != 0)
                    break;
                rem -= chunk;
            }
            close(fd);
            if (rc != 0)
                break;
            chmod(full, (mode_t)((mode & 0777) | 0600));
            if (padded > size) {
                char pad[512];
                if (gzread_exact(gz, pad, padded - (size_t)size) != 0) {
                    rc = -1;
                    break;
                }
            }
            continue;
        }

        // Skip any payload for unhandled types.
        if (padded > 0 && typeflag != '0') {
            size_t rem = padded;
            char skip[512];
            while (rem > 0) {
                size_t chunk = rem > sizeof(skip) ? sizeof(skip) : rem;
                if (gzread_exact(gz, skip, chunk) != 0) {
                    rc = -1;
                    break;
                }
                rem -= chunk;
            }
            if (rc != 0)
                break;
        }
    }

    gzclose(gz);
    return rc;
}
