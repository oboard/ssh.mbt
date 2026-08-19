/*
 * file_util.c — thin synchronous file-read helper for MoonBit native FFI.
 * Replaces the file-reading portions previously in openssl.c.
 */
#include <stdio.h>
#include <string.h>

/*
 * moonbitlang_ssh_read_file_sync(path, path_len, buf, buf_cap, out_len) -> int
 * Reads a file synchronously into a caller-provided FixedArray[Byte] buffer.
 * Returns 1 on success, 0 on error.
 */
int moonbitlang_ssh_read_file_sync(
    const char *path, int path_len,
    unsigned char *buf, int buf_cap,
    int *out_len)
{
    /* path may not be NUL-terminated; copy it */
    char tmp[4096];
    if (path_len <= 0 || path_len >= (int)sizeof(tmp)) return 0;
    memcpy(tmp, path, path_len);
    tmp[path_len] = '\0';

    FILE *fp = fopen(tmp, "rb");
    if (!fp) return 0;

    int total = 0;
    int remaining = buf_cap;
    while (remaining > 0) {
        size_t n = fread(buf + total, 1, remaining, fp);
        if (n == 0) break;
        total += (int)n;
        remaining -= (int)n;
    }
    fclose(fp);
    *out_len = total;
    return 1;
}
