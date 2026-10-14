/*
 * wckey.c — WeCom (企业微信) wxSQLite3 AES-128 数据库密钥扫描/校验器
 *
 * 原理(与 decrypt/wxwork_crypto.py 一致, 参见 https://github.com/tzwkb/wecom-agent ):
 *   - 页 size 4096, 页1 偏移 16-23 为明文 SQLite 头片段 (cipher_plaintext_header_size)
 *   - 页 key  = md5(rawkey[16] || page_no<u32 LE> || "sAlT")
 *   - IV      = SQLite3MultipleCiphers generate_initial_vector(page_no) (LCG→md5)
 *   - AES-128-CBC, reserve=0
 *   - 文件偏移 0-7 = 页1 前 16 字节密文的前 8 字节 = AES-CBC-Enc(pk1, iv1, "SQLite format 3\0")[0:8]
 *     → 该 8 字节只与 rawkey 有关, 是"密钥指纹"(KCV), 同 key 的所有库相同。
 *
 * 本工具做单块校验: 对候选 key 只需 1 次 md5 + 1 次 AES 块, 极快。
 *
 * 用法:
 *   wckey file  <path>   <kcv-hex,...>     扫描单个文件的 16B 滑窗
 *   wckey hex   <path>   <kcv-hex,...>     额外扫描 32 字符 hex 字面量窗口
 *   wckey b64   <path>   <kcv-hex,...>     再额外扫描 base64 字面量(22/24 字符 → 16B)
 *   wckey dir   <path>   <kcv-hex,...>     递归扫描目录(跳过媒体缓存/加密库)
 *   wckey pid   <pid>    <kcv-hex,...>     扫描活进程内存(需 task_for_pid 权限)
 *
 * 编译: clang -O2 -o wckey wckey.c -framework CoreFoundation
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <CommonCrypto/CommonCrypto.h>

#define MAX_TGT 8
#define PAGE_SZ 4096

static uint8_t g_pk1[16];      /* 页1 派生 key(对所有候选 key 不同) */
static uint8_t g_iv1[16];      /* 页1 IV(固定) */
static const uint8_t SQLITE_HDR[16] = "SQLite format 3";
static uint8_t g_target[MAX_TGT][8];
static int g_ntgt = 0;
static uint8_t g_found[MAX_TGT];
static uint8_t g_keys[MAX_TGT][16];
static long g_scanned = 0;
static int g_quiet = 0;
static int g_b64 = 0;          /* 是否扫描 base64 字面量(22/24 字符窗口) */

/* base64 字符表: -1 非法; '+'/'_'→62, '/'/'-'→63(同时兼容标准与 urlsafe) */
static signed char b64tab(int c) {
    if (c >= 'A' && c <= 'Z') return (signed char)(c - 'A');
    if (c >= 'a' && c <= 'z') return (signed char)(c - 'a' + 26);
    if (c >= '0' && c <= '9') return (signed char)(c - '0' + 52);
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
}

/* SQLite3MultipleCiphers 的 LCG 参数 (与 Python 端一致) */
static long long modmult(long long a, long long b, long long c, long long m, long long s) {
    long long q = s / a;
    s = b * (s - a * q) - c * q;
    if (s < 0) s += m;
    return s;
}

static void gen_iv(int page_no, uint8_t *out) {
    long long z = page_no + 1;
    uint8_t ik[16];
    for (int i = 0; i < 4; i++) {
        z = modmult(52774, 40692, 3791, 2147483399, z);
        uint32_t v = (uint32_t)(z & 0xFFFFFFFF);
        ik[i*4+0] = v & 0xff; ik[i*4+1] = (v >> 8) & 0xff;
        ik[i*4+2] = (v >> 16) & 0xff; ik[i*4+3] = (v >> 24) & 0xff;
    }
    CC_MD5(ik, 16, out);
}

/* 候选 key → 该 key 的页1 KCV 前 8 字节 */
static void kcv_of(const uint8_t *key16, uint8_t *out8) {
    uint8_t mat[24];
    memcpy(mat, key16, 16);
    mat[16] = 1; mat[17] = 0; mat[18] = 0; mat[19] = 0;
    memcpy(mat + 20, "sAlT", 4);
    uint8_t pk[16], in[16], out[16];
    CC_MD5(mat, 24, pk);
    for (int i = 0; i < 16; i++) in[i] = SQLITE_HDR[i] ^ g_iv1[i];   /* CBC 单块 */
    size_t moved = 0;
    CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionECBMode, pk, 16, NULL,
            in, 16, out, 16, &moved);
    memcpy(out8, out, 8);
}

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* 高熵过滤: 排除文本/重复/指针 */
static inline int plausible(const uint8_t *w) {
    uint8_t seen[256]; memset(seen, 0, 256);
    int distinct = 0, nonascii = 0;
    for (int i = 0; i < 16; i++) {
        uint8_t b = w[i];
        if (!seen[b]) { seen[b] = 1; distinct++; }
        if (b < 0x20 || b > 0x7e) nonascii++;
    }
    return distinct >= 11 && nonascii >= 3;
}

static int try_key(const uint8_t *key16, const char *src, long off) {
    uint8_t kcv[8];
    kcv_of(key16, kcv);
    for (int t = 0; t < g_ntgt; t++) {
        if (g_found[t]) continue;
        if (memcmp(kcv, g_target[t], 8) == 0) {
            memcpy(g_keys[t], key16, 16);
            g_found[t] = 1;
            printf("\n[FOUND] target#%d %02x%02x%02x%02x%02x%02x%02x%02x\n"
                   "        key = ", t,
                   g_target[t][0], g_target[t][1], g_target[t][2], g_target[t][3],
                   g_target[t][4], g_target[t][5], g_target[t][6], g_target[t][7]);
            for (int i = 0; i < 16; i++) printf("%02x", key16[i]);
            printf("\n        src = %s @ %ld\n", src, off);
            fflush(stdout);
        }
    }
    int rem = 0;
    for (int t = 0; t < g_ntgt; t++) if (!g_found[t]) rem++;
    return rem;
}

/* 每个未被发现的 target 都对应一个不同的候选 key, 但这里是对同一批窗口
   测试所有 target —— 因为不同 target 需要不同 key, 我们对每个 target 独立算 KCV。
   优化: 先算一次 kcv, 再与所有 target 比较。 */
/* base64 字面量: 在连续 base64 串内按 4 字符对齐试 22/24 字符窗口(解码出 16B)。
   日志/JSON/plist 里的 key 常以 base64 形式出现, 16B 滑窗与 hex 模式都漏掉这种。 */
static int try_b64_runs(const uint8_t *buf, long len, const char *src) {
    int rem = 0;
    for (int t = 0; t < g_ntgt; t++) if (!g_found[t]) rem++;
    if (rem == 0) return 0;
    for (long off = 0; off < len; ) {
        if (b64tab(buf[off]) < 0) { off++; continue; }
        long start = off;
        while (off < len && b64tab(buf[off]) >= 0) off++;
        long run = off - start;
        if (run < 22) continue;
        for (long w = start; w + 22 <= start + run; w += 4) {
            for (int wl = 22; wl <= 24 && w + wl <= start + run; wl += 2) {
                uint8_t k[16];
                unsigned acc = 0; int bits = 0, n = 0;
                for (int i = 0; i < wl && n < 16; i++) {
                    acc = (acc << 6) | (unsigned)b64tab(buf[w + i]);
                    bits += 6;
                    if (bits >= 8) { bits -= 8; k[n++] = (uint8_t)((acc >> bits) & 0xffu); }
                }
                if (n == 16 && plausible(k)) {
                    rem = try_key(k, src, w);
                    if (rem == 0) return 0;
                }
            }
        }
    }
    return rem;
}

static int scan_buf(const uint8_t *buf, long len, const char *src, int try_hex) {
    int rem = 0;
    for (int t = 0; t < g_ntgt; t++) if (!g_found[t]) rem++;
    if (rem == 0) return 0;

    if (g_b64) {
        rem = try_b64_runs(buf, len, src);
        if (rem == 0) return 0;
    }

    for (long off = 0; off + 16 <= len; off++) {
        const uint8_t *w = buf + off;
        if (plausible(w)) {
            int r = try_key(w, src, off);
            rem = 0;
            for (int t = 0; t < g_ntgt; t++) if (!g_found[t]) rem++;
            if (rem == 0) return 0;
        }
        if (try_hex && off + 32 <= len) {
            int ok = 1;
            int hv[32];
            for (int i = 0; i < 32; i++) {
                hv[i] = hexval(w[i]);
                if (hv[i] < 0) { ok = 0; break; }
            }
            if (ok) {
                uint8_t k[16];
                for (int i = 0; i < 16; i++) k[i] = (uint8_t)((hv[2*i] << 4) | hv[2*i+1]);
                if (plausible(k)) {
                    int r = try_key(k, src, off);
                    rem = 0;
                    for (int t = 0; t < g_ntgt; t++) if (!g_found[t]) rem++;
                    if (rem == 0) return 0;
                }
            }
        }
    }
    return rem;
}

static int scan_file(const char *path, int try_hex) {
    FILE *f = fopen(path, "rb");
    if (!f) return g_ntgt;
    size_t cap = 8 * 1024 * 1024;
    uint8_t *buf = malloc(cap + 32);
    if (!buf) { fclose(f); return g_ntgt; }
    long total = 0;
    for (;;) {
        size_t n = fread(buf, 1, cap, f);
        if (n == 0) break;
        total += (long)n;
        g_scanned += (long)n;
        int rem = scan_buf(buf, (long)n, path, try_hex);
        if (rem == 0) break;
        if (n < cap) break;
    }
    free(buf);
    fclose(f);
    return 0;
}

static const char *SKIP_DIRS[] = {
    "Caches/Images", "Caches/Videos", "Caches/Files", "Caches/Emotions",
    "Caches/Emotion_Thumbnail", "Caches/Video_Thumbnail", "Caches/Voices",
    "Emotion", "Avator", "cefcache", "Cache/File", "Cache/Image",
    "tmp", "Log", "WeDrive", "crashpad",
    NULL
};

static int skip_path(const char *p) {
    for (int i = 0; SKIP_DIRS[i]; i++)
        if (strstr(p, SKIP_DIRS[i])) return 1;
    return 0;
}

static void walk(const char *dir, int try_hex, int max_mb) {
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    char path[4096];
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.') continue;
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        if (skip_path(path)) continue;
        struct stat st;
        if (lstat(path, &st) != 0) continue;
        if (S_ISLNK(st.st_mode)) continue;
        if (S_ISDIR(st.st_mode)) {
            walk(path, try_hex, max_mb);
            int rem = 0;
            for (int t = 0; t < g_ntgt; t++) if (!g_found[t]) rem++;
            if (rem == 0) { closedir(d); return; }
        } else if (S_ISREG(st.st_mode)) {
            if (max_mb > 0 && st.st_size > (off_t)max_mb * 1024 * 1024) continue;
            scan_file(path, try_hex);
        }
    }
    closedir(d);
}

/* ---- 活进程内存扫描 (需要 task_for_pid 权限: 目标进程须有 get-task-allow) ---- */
#include <mach/mach.h>
#include <mach/mach_vm.h>

/* 分片: 环境变量 WCKEY_SHARD/WCKEY_NSHARD 让多个进程并行扫不同内存区(只读, 互不干扰) */
static long g_shard = 0, g_nshard = 1;

static int scan_pid(int pid) {
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "task_for_pid(%d) 失败 kr=%d (需目标进程具备 get-task-allow)\n", pid, kr);
        return 1;
    }
    mach_vm_address_t addr = 0;
    mach_vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj = MACH_PORT_NULL;
    long regions = 0, mine = 0;
    while (1) {
        kr = mach_vm_region(task, &addr, &size, VM_REGION_BASIC_INFO_64,
                            (vm_region_info_t)&info, &cnt, &obj);
        if (kr != KERN_SUCCESS) break;
        long idx = regions++;
        if (g_nshard > 1 && (idx % g_nshard) != g_shard) { addr += size; continue; }
        if (size > 0 && size < 512ull * 1024 * 1024) {
            void *buf = malloc(size);
            if (buf) {
                mach_vm_size_t out = 0;
                if (mach_vm_read_overwrite(task, addr, size, (mach_vm_address_t)buf, &out) == KERN_SUCCESS) {
                    g_scanned += (long)out;
                    mine++;
                    if (mine % 200 == 0 && !g_quiet)
                        fprintf(stderr, "  ...%ld MB / %ld 区(shard %ld/%ld)\n",
                                g_scanned / 1024 / 1024, mine, g_shard, g_nshard);
                    int rem = scan_buf(buf, (long)out, "mem", 1);
                    if (rem == 0) { free(buf); break; }
                }
                free(buf);
            }
        }
        addr += size;
    }
    if (!g_quiet) fprintf(stderr, "扫描 %ld MB / %ld 区(shard %ld/%ld)\n",
                          g_scanned / 1024 / 1024, mine, g_shard, g_nshard);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr,
            "用法:\n"
            "  %s file <path> <kcv1,kcv2,...>         单文件 16B 滑窗\n"
            "  %s hex  <path> <kcv...>                单文件 + 32字符hex字面量\n"
            "  %s dir  <path> <kcv...> [maxMB]        递归扫描(默认跳过媒体/日志)\n"
            "  %s dirall <path> <kcv...> [maxMB]      递归扫描(不跳过)\n"
            "  %s pid  <pid>  <kcv...>                活进程内存扫描\n", argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 2;
    }
    const char *mode = argv[1];
    gen_iv(1, g_iv1);
    /* 可选分片(并行扫描): WCKEY_SHARD=i WCKEY_NSHARD=n */
    if (getenv("WCKEY_SHARD")) g_shard = atol(getenv("WCKEY_SHARD"));
    if (getenv("WCKEY_NSHARD")) g_nshard = atol(getenv("WCKEY_NSHARD"));
    if (g_nshard < 1) g_nshard = 1;
    /* 解析目标 KCV */
    char *spec = strdup(argv[3]);
    char *save = NULL;
    for (char *tok = strtok_r(spec, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        if (g_ntgt >= MAX_TGT) break;
        if (strlen(tok) != 16) { fprintf(stderr, "KCV 必须是 16 个 hex 字符: %s\n", tok); return 2; }
        for (int i = 0; i < 8; i++) {
            int hi = hexval(tok[2*i]), lo = hexval(tok[2*i+1]);
            if (hi < 0 || lo < 0) { fprintf(stderr, "KCV 非法: %s\n", tok); return 2; }
            g_target[g_ntgt][i] = (uint8_t)((hi << 4) | lo);
        }
        g_ntgt++;
    }
    printf("目标 KCV: ");
    for (int t = 0; t < g_ntgt; t++) {
        printf("#%d=", t);
        for (int i = 0; i < 8; i++) printf("%02x", g_target[t][i]);
        printf(" ");
    }
    printf("\n");

    if (strcmp(mode, "pid") == 0) {
        g_b64 = 1;
        scan_pid(atoi(argv[2]));
    } else if (strcmp(mode, "file") == 0) {
        scan_file(argv[2], 0);
    } else if (strcmp(mode, "hex") == 0) {
        scan_file(argv[2], 1);
    } else if (strcmp(mode, "b64") == 0) {
        g_b64 = 1;
        scan_file(argv[2], 1);
    } else if (strcmp(mode, "dir") == 0 || strcmp(mode, "dirall") == 0) {
        g_b64 = 1;
        if (strcmp(mode, "dirall") == 0) SKIP_DIRS[0] = NULL;
        int max_mb = (argc > 4) ? atoi(argv[4]) : 0;
        walk(argv[2], 1, max_mb);
    } else {
        fprintf(stderr, "未知模式 %s\n", mode);
        return 2;
    }

    int hits = 0;
    for (int t = 0; t < g_ntgt; t++) if (g_found[t]) hits++;
    printf("\n扫描 %.1f MB, 命中 %d/%d\n", g_scanned / 1048576.0, hits, g_ntgt);
    for (int t = 0; t < g_ntgt; t++) {
        if (g_found[t]) {
            printf("target#%d key=", t);
            for (int i = 0; i < 16; i++) printf("%02x", g_keys[t][i]);
            printf("\n");
        }
    }
    return hits > 0 ? 0 : 1;
}
