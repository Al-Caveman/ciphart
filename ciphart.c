/*
 *  ciphart - XChacha20 KDF and file encrypt/decrypt.
 *  Copyright (C) 2020 caveman
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

#include "license.h"    /* WARRANTY, CONDITIONS */
#include <errno.h>      /* errno */
#include <fcntl.h>      /* open */
#include <inttypes.h>   /* PRIu64, UINT64_C */
#include <math.h>       /* log2 */
#include <pthread.h>    /* pthread_* */
#include <sodium.h>     /* crypto_*, sodium_* */
#include <stdarg.h>     /* va_* */
#include <stdint.h>     /* uint64_t, uint32_t */
#include <stdio.h>      /* printf, fprintf, vfprintf, va_*, freadf, feof,
                            rewind, fputs */
#include <stdlib.h>     /* strtoull, strtod, exit */
#include <string.h>     /* strcmp, strlen */
#include <sys/stat.h>   /* open */
#include <sys/types.h>  /* open */
#include <termios.h>    /* tcgetattr, tcsetattr */
#include <time.h>       /* time */
#include <unistd.h>     /* getopt, isatty, STDOUT_FILENO, STDERR_FILENO,
                            tcgetattr, tcsetattr, write  */

#define APP_NAME "ciphart"
#define APP_VERSION "5.0.0"
#define APP_YEAR "2020"
#define APP_URL "https://github.com/Al-Caveman/ciphart"
#define ARG_PARSE_OK 0
#define ARG_PARSE_ERR 1
#define FILE_MODE_PLAIN (S_IRUSR | S_IWUSR)
#define DEV_TTY "/dev/tty"
#define SIZE_NONCE crypto_stream_xchacha20_NONCEBYTES
#define SIZE_HEADER crypto_secretstream_xchacha20poly1305_HEADERBYTES
#define SIZE_KEY crypto_secretstream_xchacha20poly1305_KEYBYTES
#define DFLT_PATH_IN "-"
#define DFLT_PATH_OUT "-"
#define DFLT_PAD_SIZE 999997440llu /* bytes for the whole memory pad */
#define DFLT_TASK_SIZE 4096llu /* bytes per task in the memory pad */
#define DFLT_TASK_ROUNDS UINT64_C(1) /* rounds per task */
#define DFLT_ENTRPY 20
#define DFLT_THREADS 4 /* number of threads */
#define ENTRPY_MAX 63
#define UI_UPDATE_THRESHOLD 100000
#define FLAG_E  1       /* encrypt */
#define FLAG_D  2       /* decrypt */
#define FLAG_K  4       /* dereive new key */
#define FLAG_W  8       /* show warning */
#define FLAG_C  16      /* show conditions */
#define FLAG_H  32      /* show help */
#define FLAG_S  64      /* get password from stdin */
#define FLAG_Z  128     /* disable password confirmation */
#define FLAG_I  256     /* input path */
#define FLAG_O  512     /* output path */
#define FLAG_M  1024    /* memory pad's size */
#define FLAG_T  2048    /* teach task's size in the pad */
#define FLAG_R  4096    /* number of rounds in each task */
#define FLAG_N  8192    /* number of entropy bits */
#define FLAG_J  16384   /* number of worker threads */
#define FLAG_V  32768   /* enable verbose output mode */
#define TIME_LEFT_DESC_SIZE 500 /* number of characters */
#define RETURN_OK           0 /* maybe no problem               */
#define RETURN_FAIL         1 /* a problem                      */
#define RETURN_FAIL_SODIUM  2 /* libsodium didn't load          */
#define RETURN_FAIL_ARGS    3 /* command arg parsing problems   */
#define RETURN_FAIL_IO      4 /* file read/write problems       */
#define RETURN_FAIL_MEM     5 /* memory allocation problems     */
#define RETURN_FAIL_PTHREAD 6 /* pthread failure                */
#define RETURN_FAIL_BADPASS 7 /* bad password or corrupt file   */
#define RETURN_FAIL_BADEND  8 /* premature input file end       */
#define CEOF_OK   0 /* ciphart_eof success */
#define CEOF_EOF  1 /* ciphart_eof eof */
#define CEOF_FAIL 2 /* ciphart_eof failure */
#define CEOF_UNKNOWN 3 /* ciphart_eof failure */

/* 1 = verbose, 0 not */
int verbose = 0;

/* print error */
void ciphart_err(const char *fmt, ...);

/* print warning */
void ciphart_warn(const char *fmt, ...);

/* print info */
void ciphart_info(const char *fmt, ...);

/* print banner */
void ciphart_banner(char *exec_name);

/* print help */
void ciphart_help(char *exec_name);

/* fputs */
int ciphart_fputs(const char *s);

/* arg parser */
int ciphart_parse_args(
    int argc, char **argv, int *flags,
    int *pass_stdin, int *pass_confirm, char **path_in, char **path_out,
    size_t *pad_size, size_t *task_size, uint64_t *task_rounds,
    int *entropy, size_t *threads
);

/* obtain key from password from STDIN */
int ciphart_get_key(
    int flags,
    unsigned char *buf_pass, unsigned char *key,
    crypto_generichash_state *state,
    unsigned char *key_confirm, int pass_stdin, int pass_confirm
);

/* convert strings into numbers within range */
int ciphart_str2size_t(
    char f, const char *s, size_t min, size_t max, size_t *out);
int ciphart_str2uint64_t(
    char f, const char *s, size_t min, size_t max, size_t *out);
int ciphart_str2int(
    char f, const char *s, int min, int max, int *out);
int ciphart_str2double(
    const char *s, double min, double max, double *out);

/* struct defining ciphart_thread argument */
struct thread_arg {
    unsigned char   *pad;
    unsigned char   *nonce;
    unsigned char   *key;
    uint64_t        *xor;
    pthread_mutex_t *mutex_xor;
    int              r;
    size_t           tasks;
    size_t           task_size;
    uint64_t         task_rounds;
    uint64_t         pad_id;
    uint64_t         first_task_id;
};

/* worker thread */
void *ciphart_thread(void *arg);

/* derive a more expensive key */
int ciphart_complicate(
    size_t pad_size, size_t task_size,
    uint64_t pads, uint64_t task_rounds, size_t threads,
    unsigned char *key, pthread_t *ids, struct thread_arg *a,
    unsigned char *nonces, uint64_t *xor
);

/* predicts times needed to completion */
char *ciphart_oracle(
    uint64_t tasks_done, uint64_t tasks_total,
    time_t time_start, char *time_left_desc
);

/* unbuffered chunk reader to detect end-of-file without an extra round
 * with zery-bytes read.  this is necessary to let libsodium's encryption
 * work peacefully, as it assumes that each encrypted chunk is of a given
 * size, except the last one.  basically this tries to feel like feof,
 * except for not using buffered i/o */
int ciphart_eof(int fd, unsigned char *buf, size_t count, ssize_t *read);

/* encrypt input into output */
int ciphart_enc(
    unsigned char *key, unsigned char *header,
    crypto_secretstream_xchacha20poly1305_state *state,
    unsigned char *buf_cleartext, unsigned char *buf_ciphertext,
    size_t chunk_clr, char *path_in, char *path_out
);

/* decrypt input into output */
int ciphart_dec(
    unsigned char *key, unsigned char *header,
    crypto_secretstream_xchacha20poly1305_state *state,
    unsigned char *buf_ciphertext, unsigned char *buf_cleartext,
    size_t chunk_enc, char *path_in, char *path_out
);

int main(int argc, char **argv) {
    int r = RETURN_FAIL;
    int fd_kdf = -1;
    void *moah = NULL;
    char *exec_name = argv[0];

    /* assign default values */
    int pass_stdin = 0;
    int pass_confirm = 1;
    char *path_in = DFLT_PATH_IN;
    char *path_out = DFLT_PATH_OUT;
    size_t pad_size = DFLT_PAD_SIZE;
    size_t task_size = DFLT_TASK_SIZE;
    uint64_t task_rounds = DFLT_TASK_ROUNDS;
    int entropy = DFLT_ENTRPY;
    size_t threads = DFLT_THREADS;

    /* parse arguments */
    int flags = 0;
    int args_r = ciphart_parse_args(
        argc, argv, &flags,
        &pass_stdin, &pass_confirm, &path_in, &path_out,
        &pad_size, &task_size, &task_rounds,
        &entropy, &threads
    );
    if (args_r) {
        fprintf(stderr, "\ntype `%s -h` for help.\n", exec_name);
        return RETURN_FAIL_ARGS;
    }

    /* do the easy actions */
    if (flags & FLAG_K && ! (flags & (FLAG_E | FLAG_D))) {
        ciphart_warn("entropy is calculated based on xchacha20");
    } else if (flags & FLAG_W) {
        ciphart_banner(exec_name);
        ciphart_fputs(WARRANTY);
        return RETURN_OK;
    } else if (flags & FLAG_C) {
        ciphart_banner(exec_name);
        ciphart_fputs(CONDITIONS);
        ciphart_fputs(CONDITIONS_1);
        ciphart_fputs(CONDITIONS_2);
        ciphart_fputs(CONDITIONS_3);
        ciphart_fputs(CONDITIONS_4);
        ciphart_fputs(CONDITIONS_5);
        ciphart_fputs(CONDITIONS_6_a);
        ciphart_fputs(CONDITIONS_6_b);
        ciphart_fputs(CONDITIONS_7);
        ciphart_fputs(CONDITIONS_8);
        ciphart_fputs(CONDITIONS_9);
        ciphart_fputs(CONDITIONS_10);
        ciphart_fputs(CONDITIONS_11);
        ciphart_fputs(CONDITIONS_12);
        ciphart_fputs(CONDITIONS_13);
        ciphart_fputs(CONDITIONS_14);
        ciphart_fputs(CONDITIONS_15);
        ciphart_fputs(CONDITIONS_16);
        ciphart_fputs(CONDITIONS_17);
        return RETURN_OK;
    } else if (flags & FLAG_H) {
        ciphart_banner(exec_name);
        ciphart_help(exec_name);
        return RETURN_OK;
    }

    /* correct memory into multiples of task_size*2 */
    if (pad_size % (task_size * 2)) {
        ciphart_warn(
            "'-m %zu' is not a multiple of %zu (i.e. 2 * '-t INT').",
            pad_size, task_size * 2
        );
        pad_size -= pad_size % (task_size * 2);
        pad_size += task_size * 2;
        ciphart_warn("using '-m %zu' instead...", pad_size);
    }

    /* update chunk/buffer sizes of clear and cipher texts to match task
     * sizes.  this is required in order to guarantee that key derivation's
     * entropy holds */
    size_t chunk_clr = task_size;
    size_t chunk_enc = chunk_clr \
                       + crypto_secretstream_xchacha20poly1305_ABYTES;

    /* make sure that the requested entropy is large enough to result in
     * working in the pad twice.  because twice is the smallest number that
     * the cross-tax xor-ing happens (to introduce memory hardness) */
    uint64_t tasks = pad_size / task_size;
    uint64_t pads = (1llu << entropy) / tasks / task_rounds;
    if (pads < 2) {
        ciphart_warn(
            "'-n %d' is too small for '-m %zu -t %zu -r %llu'.",
            entropy, pad_size, task_size, task_rounds
        );
        do {
            if (entropy > ENTRPY_MAX) {
                ciphart_err(
                    "no entropy can satisfy '-m %zu -t %zu -r %llu'.",
                    pad_size, task_size, task_rounds
                );
                return RETURN_FAIL_ARGS;
            }
            entropy++;
            pads = (1llu << entropy) / tasks / task_rounds;
        } while (pads < 2);
        ciphart_warn("using '-n %d' instead...", entropy);
    }

    /* add one extra pad if there were remainders */
    if (
        (1llu << entropy) % tasks
        || (1llu << entropy) / tasks % task_rounds
    ) {
        pads++;
    }

    /* print settings' summary */
    if (verbose && flags & FLAG_K) {
        ciphart_info(
            "key derivation's settings: -m%zu -t%zd -r%llu -n%d",
            pad_size, task_size, task_rounds, entropy
        );
    }

    /* initialise libsodium */
    if (sodium_init() != 0) {
        ciphart_err("failed to initialise libsodium.");
        r = RETURN_FAIL_SODIUM;
        goto fail;
    }

    /* securely malloc ~\o The Mother of All Heaps (moah) o/~
     *
     *                           the life of moah
     * ------------------------------- time ----------------------------->
     * PHASE 0          PHASE 1             PHASE 2         PHASE 3
     * getting key      deriving new key    header/state    enc/dec
     * ------------------------------- time ----------------------------->
     *
     * key----------------------------------*
     * key_confirm*     ids---*             cipher_state----*
     * buf_pass---*     args--*             header*         buf_cleartext
     * hash_state-*     nonces*                             buf_ciphertext
     *                  xor---*
     */
    size_t moah_phases[4];
    moah_phases[0] = SIZE_KEY + SIZE_KEY + 1 \
                     + sizeof(crypto_generichash_state);
    moah_phases[1] = SIZE_KEY                              \
                     + threads * sizeof(pthread_t)         \
                     + threads * sizeof(struct thread_arg) \
                     + threads * SIZE_NONCE                \
                     + sizeof(uint64_t);
    moah_phases[2] = SIZE_KEY + SIZE_HEADER \
                     + sizeof(crypto_secretstream_xchacha20poly1305_state);
    moah_phases[3] = chunk_clr + chunk_enc + SIZE_KEY \
                     + sizeof(crypto_secretstream_xchacha20poly1305_state);
    moah_phases[3] = SIZE_KEY \
                     + sizeof(crypto_secretstream_xchacha20poly1305_state) \
                     + chunk_clr + chunk_enc;
    size_t moah_size = 0;
    int phase_id;
    for (phase_id = 0; phase_id < 4; phase_id++) {
        if (moah_phases[phase_id] > moah_size) {
            moah_size = moah_phases[phase_id];
        }
    }
    moah = sodium_malloc(moah_size);
    if (moah == NULL) {
        ciphart_err("failed to allocate memory.");
        return RETURN_FAIL_MEM;
    }

    /* partition moah */
    /* phase 0 */
    unsigned char *key = moah;
    unsigned char *key_confirm = key + SIZE_KEY;
    unsigned char *buf_pass = key_confirm + SIZE_KEY;
    crypto_generichash_state *hash_state = (void *)(buf_pass + 1);
    /* phase 1 */
    pthread_t *ids = (void *)key_confirm;
    struct thread_arg *args = (void *)(ids + threads);
    unsigned char *nonces = (void *)(args + threads);
    uint64_t *xor = (uint64_t *)(nonces + threads * SIZE_NONCE);
    /* phase 2 */
    crypto_secretstream_xchacha20poly1305_state *cipher_state = \
        (void *)ids;
    unsigned char *header = (void *)(cipher_state + 1);
    /* phase 3 */
    unsigned char *buf_cleartext = header;
    unsigned char *buf_ciphertext = buf_cleartext + chunk_clr;

    /* get key */
    int key_r = ciphart_get_key(
        flags, buf_pass, key, hash_state, key_confirm, pass_stdin,
        pass_confirm
    );
    if (key_r) {
        r = key_r;
        goto fail;
    }

    /* derive a more expensive key that's worth 'entropy' bits */
    if (flags & FLAG_K) {
        if (verbose)
            ciphart_info(
                "deriving a better key worth ~%d more entropy bits...",
                entropy
            );
        int kdf_r = ciphart_complicate(
                pad_size, task_size, pads, task_rounds, threads,
                key, ids, args, nonces, xor
            );
        if (kdf_r) {
            r = key_r;
            goto fail;
        }
    }

    /* kdf only? */
    if (flags & FLAG_K && ! (flags & (FLAG_E | FLAG_D))) {
        if (strcmp(path_out, "-") == 0) {
            fd_kdf = STDOUT_FILENO;
        } else {
            fd_kdf = open(
                path_out, O_WRONLY | O_CREAT | O_TRUNC, FILE_MODE_PLAIN
            );
            if (fd_kdf == -1) {
                ciphart_err("failed to open '%s' for write", path_out);
                r = RETURN_FAIL_IO;
                goto fail;
            }
        }
        if (write(fd_kdf, key, SIZE_KEY) != SIZE_KEY) {
            ciphart_err("failed to fully write to '%s'", path_out);
            r = RETURN_FAIL_IO;
            goto fail;
        }
        goto success;
    }

    /* encrypt input into output? */
    if (flags & FLAG_E) {
        if (verbose)
            ciphart_info(
                "encrypting '%s' into '%s'...", path_in, path_out
            );
        int r_enc = ciphart_enc(
            key, header, cipher_state, buf_cleartext, buf_ciphertext,
            chunk_clr, path_in, path_out
        );
        if (r_enc) {
            r = r_enc;
            goto fail;
        }
        goto success;
    }

    /* decrypt input into output? */
    if (flags & FLAG_D) {
        if (verbose)
            ciphart_info(
                "decrypting '%s' into '%s'...", path_in, path_out
            );
        int r_dec = ciphart_dec(
            key, header, cipher_state, buf_ciphertext, buf_cleartext,
            chunk_enc, path_in, path_out
        );
        if (r_dec) {
            r = r_dec;
            goto fail;
        }
        goto success;
    }

    /* unknown action */
    ciphart_err("unknown action");
    r = RETURN_FAIL_ARGS;
    goto fail;

success:
    r = RETURN_OK;
fail:
    if (moah != NULL) sodium_free(moah);
    if (fd_kdf != -1 && strcmp(path_out, "-") && close(fd_kdf))
        ciphart_err("failed to close '%s'", path_out);
    return r;
}

/* print error */
void ciphart_err(const char *fmt, ...) {
    fprintf(stderr,"ERROR: ");
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr,"\n");
}

/* print warning */
void ciphart_warn(const char *fmt, ...) {
    fprintf(stderr,"WARNIG: ");
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr,"\n");
}

/* print info */
void ciphart_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr,"\n");
}

/* print banner */
void ciphart_banner(char *exec_name) {
    fprintf(
        stdout,
        "%s v%s  copyright (C) %s  caveman\n"
        "%s\n\n"
        "this program comes with ABSOLUTELY NO WARRANTY; for details\n"
        "type `%s -w'.  this is free software, and you are welcome to\n"
        "redistribute it under certain conditions; type `%s -c' for\n"
        "details.\n\n",
        APP_NAME, APP_VERSION, APP_YEAR, APP_URL, exec_name,
        exec_name
    );
}

/* print help */
void ciphart_help(char *exec_name) {
    fprintf(
        stdout,
        "SYNOPSIS\n"
        " %s -k       [KDF ...]           [-o PATH] [-s]      [-v]\n"
        " %s -ke      [KDF ...] [-i PATH] [-o PATH] [-s] [-z] [-v]\n"
        " %s -kd      [KDF ...] [-i PATH] [-o PATH] [-s]      [-v]\n"
        " %s -e                 [-i PATH] [-o PATH] [-s] [-z] [-v]\n"
        " %s -d                 [-i PATH] [-o PATH] [-s]      [-v]\n"
        " %s -{w,c,h}\n\n"

        "ACTIONS\n"
        " -k        only derive a better key.\n"
        " -ke       derives a better key and encrypts input into output.\n"
        " -kd       derives a better key and decrypts input into output.\n"
        " -e        only encrypt input into output ciphertext.\n"
        " -d        only decrypt input into output plaintext.\n"
        " -w        show warranty notice.\n"
        " -c        show usage conditions.\n"
        " -h        show this help.\n\n"

        "OPTIONS\n"
        " -i PATH   path to input file.  default is '-' for STDIN.\n"
        " -o PATH   path to output file.  default is '-' for STDOUT.\n"
        " -s        read passwords via STDIN.\n"
        " -z        disable password confirmation.\n"
        " -v        enable verbose output.\n\n"

        "KDF\n"
        " -m NUM    size of memory pad.  default is '%llu'.\n"
        " -t NUM    bytes of each task in the pad.  default is '%llu'.\n"
        " -r NUM    repetition in each task.  default is '%"PRId64"'.\n"
        " -n NUM    entropy bits.  default is '%d'.\n"
        " -j NUM    number of concurrent threads.  default is '%d'.\n\n"

        "VALUES\n"
        " PATH      file path.  '-' means STDIN or STDOUT.\n"
        " NUM       positive integer.\n\n"

        "RETURN CODES\n"
        " %d         success.\n"
        " %d         general failure.\n"
        " %d         libsodium failure.\n"
        " %d         argument parsing failure.\n"
        " %d         io failure.\n"
        " %d         memory allocation failure.\n"
        " %d         pthread feailure.\n"
        " %d         bad password or corrupted input.\n"
        " %d         premature input end.\n",
        /* synopsis */
        exec_name, exec_name, exec_name, exec_name, exec_name, exec_name,
        /* actions */
        /* options */
        /* kdf */
        DFLT_PAD_SIZE, DFLT_TASK_SIZE, DFLT_TASK_ROUNDS, DFLT_ENTRPY,
        DFLT_THREADS,
        /* values */
        /* return codes */
        RETURN_OK, RETURN_FAIL, RETURN_FAIL_SODIUM,
        RETURN_FAIL_ARGS, RETURN_FAIL_IO, RETURN_FAIL_MEM,
        RETURN_FAIL_PTHREAD, RETURN_FAIL_BADPASS, RETURN_FAIL_BADEND
    );
}

/* fputs */
int ciphart_fputs(const char *s) {
    if (fputs(s, stdout) == EOF) {
        ciphart_err("fputs failed.");
        return RETURN_FAIL_IO;
    }
    return RETURN_OK;
}

/* arg parser */
int ciphart_parse_args(
    int argc, char **argv, int *flags,
    int *pass_stdin, int *pass_confirm, char **path_in, char **path_out,
    size_t *pad_size, size_t *task_size, uint64_t *task_rounds,
    int *entropy, size_t *threads
) {
    int arg_parse_err = ARG_PARSE_OK, opt;
    while ((opt = getopt(
        argc, argv, "-:eEdDkKwchi:o:m:t:r:n:j:szv"
    )) != -1) {
        switch (opt) {
            /* actions */
            case 'e': /* can only be mixed with key derivation */
                *flags |= FLAG_E;
                break;
            case 'd': /* can be mixed with key derivation */
                *flags |= FLAG_D;
                break;
            case 'k': /* can be mixed with encryption and decryption */
                *flags |= FLAG_K;
                break;
            case 'w':
                *flags |= FLAG_W;
                break;
            case 'c':
                *flags |= FLAG_C;
                break;
            case 'h':
                *flags |= FLAG_H;
                break;

            /* options */
            case 's': /* read passwords from stdin instead of /dev/tty */
                *pass_stdin = 1;
                *flags |= FLAG_S;
                break;
            case 'z': /* disable password confirmation */
                *pass_confirm = 0;
                *flags |= FLAG_Z;
                break;
            case 'i': /* input path */
                *path_in = optarg;
                *flags |= FLAG_I;
                break;
            case 'o': /* output path */
                *path_out = optarg;
                *flags |= FLAG_O;
                break;
            case 'm': /* total memory for the pad */
                if (ciphart_str2size_t(
                    'm', optarg, sizeof(uint64_t) * 4, SIZE_MAX, pad_size
                )) arg_parse_err = ARG_PARSE_ERR;
                *flags |= FLAG_M;
                break;
            case 't': /* size of each task in the pad */
                if (ciphart_str2size_t(
                    't', optarg, sizeof(uint64_t) * 2, SIZE_MAX / 2,
                    task_size
                )) arg_parse_err = ARG_PARSE_ERR;
                *flags |= FLAG_T;
                break;
            case 'r': /* rounds in each task */
                if (ciphart_str2uint64_t(
                    'r', optarg, 1, UINT64_MAX / 2, task_rounds
                )) arg_parse_err = ARG_PARSE_ERR;
                *flags |= FLAG_R;
                break;
            case 'n': /* entropy bits */
                if (ciphart_str2int(
                    'n', optarg, 0, ENTRPY_MAX, entropy
                )) arg_parse_err = ARG_PARSE_ERR;
                *flags |= FLAG_N;
                break;
            case 'j': /* number of concurrent threads */
                if (ciphart_str2size_t(
                    'j', optarg, 1, SIZE_MAX / sizeof(struct thread_arg),
                    threads
                )) arg_parse_err = ARG_PARSE_ERR;
                *flags |= FLAG_J;
                break;
            case 'v': /* verbose mode */
                verbose = 1;
                *flags |= FLAG_V;
                break;

            /* getopt's errors */
            case 1:
                ciphart_err("unknown value '%s'.", optarg);
                arg_parse_err = ARG_PARSE_ERR;
                break;
            case '?':
                ciphart_err("unknown flag '%c'.", optopt);
                arg_parse_err = ARG_PARSE_ERR;
                break;
            case ':':
                ciphart_err("flag '%c' lacks a value.", optopt);
                arg_parse_err = ARG_PARSE_ERR;
                break;
            default:
                ciphart_err("unknown argument parsing error.");
                arg_parse_err = ARG_PARSE_ERR;
        }
    }

    /* detect bad combination of options */
    /* some action must be chosen */
    if (
        ! (*flags & (FLAG_E | FLAG_D | FLAG_K | FLAG_W | FLAG_C | FLAG_H))
    ) {
        ciphart_err(
            "an action must be chosen."
        );
        arg_parse_err = ARG_PARSE_ERR;
    }

    /* key derivation options are valid only with '-k' */
    if (
        *flags & (FLAG_T | FLAG_R | FLAG_N | FLAG_J) && ! (*flags & FLAG_K)
    ) {
        ciphart_err(
            "options '-m', '-t', '-r' and '-j' are valid only with '-k'."
        );
        arg_parse_err = ARG_PARSE_ERR;
    }

    /* '-s' is only valid for enc/dec/key derivation */
    if (*flags & FLAG_S && ! (*flags & (FLAG_E | FLAG_D | FLAG_K))) {
        ciphart_err(
            "option '-s' is valid only with '-e', '-d', or '-k'.");
        arg_parse_err = ARG_PARSE_ERR;
    }

    /* '-z' is only valid for enc */
    if (*flags & FLAG_Z && ! (*flags & FLAG_E)) {
        ciphart_err(
            "option '-z' is valid only with '-e' or '-ke'.");
        arg_parse_err = ARG_PARSE_ERR;
    }

    /* '-z' is invalid for help/warn/cond */
    if (*flags & FLAG_V && (*flags & (FLAG_H | FLAG_W | FLAG_C))) {
        ciphart_err(
            "option '-v' is invalid for '-h', '-w' and '-w'.");
        arg_parse_err = ARG_PARSE_ERR;
    }

    /* '-i' is only valid for enc/dec */
    if (*flags & FLAG_I && ! (*flags & (FLAG_E | FLAG_D))) {
        ciphart_err(
            "option '-i' is valid only with '-e' and '-d'.");
        arg_parse_err = ARG_PARSE_ERR;
    }

    /* '-o' is only valid for enc/dec/key derivation */
    if (*flags & FLAG_O && ! (*flags & (FLAG_E | FLAG_D | FLAG_K))) {
        ciphart_err(
            "option '-o' is valid only with '-e', '-d' and '-k'.");
        arg_parse_err = ARG_PARSE_ERR;
    }

    /* '-e' and '-d' do not mix with each other */
    if (*flags & FLAG_E && *flags & FLAG_D) {
        ciphart_err(
            "actions '-e' and '-d' do not mix with each other.");
        arg_parse_err = ARG_PARSE_ERR;
    }

    /* '-w' does not mix with any other action */
    if (
        *flags & FLAG_W
        && *flags & (FLAG_E | FLAG_D | FLAG_K | FLAG_C | FLAG_H)
    ) {
        ciphart_err(
            "action '-w' does not mix with others.");
        arg_parse_err = ARG_PARSE_ERR;
    }

    /* '-c' does not mix with any other action */
    if (
        *flags & FLAG_C
        && *flags & (FLAG_E | FLAG_D | FLAG_K | FLAG_W | FLAG_H)
    ) {
        ciphart_err(
            "action '-c' does not mix with others.");
        arg_parse_err = ARG_PARSE_ERR;
    }

    /* '-h' does not mix with any other action */
    if (
        *flags & FLAG_H
        && *flags & (FLAG_E | FLAG_D | FLAG_K | FLAG_W | FLAG_C)
    ) {
        ciphart_err(
            "action '-h' does not mix with others.");
        arg_parse_err = ARG_PARSE_ERR;
    }

    /* make sure input and output paths are not the same file */
    if (strcmp(*path_in, "-") != 0 && strcmp(*path_in, *path_out) == 0) {
        ciphart_err("input and output paths cannot be the same file.");
        arg_parse_err = ARG_PARSE_ERR;
    }

    return arg_parse_err;
}

/* obtain key from password from STDIN */
int ciphart_get_key(
    int flags,
    unsigned char *buf_pass, unsigned char *key,
    crypto_generichash_state *state,
    unsigned char *key_confirm, int pass_stdin, int pass_confirm
) {
    int r = RETURN_FAIL;

    /* should password be taken from /dev/tty?  or stdin? */
    int fd;
    char *prompts[2];
    if (pass_stdin) {
        fd = STDIN_FILENO;
        prompts[0] = "reading password from STDIN (end by newline)...";
        prompts[1] = "confirming password from STDIN (end by newline)...";
    } else {
        fd = open(DEV_TTY, O_RDWR | O_NOCTTY);
        prompts[0] = "password: ";
        prompts[1] = "confirming password: ";
        if (fd == -1) {
            ciphart_err("failed to open '%s' for read.", DEV_TTY);
            r = RETURN_FAIL_IO;
            goto fail;
        }
    }

    /* obtain password */
    unsigned char attempt = 0;
    unsigned char *buf_tmp;
    struct termios termios_old, termios_new;
    while (1) {
        /* disable terminal echo */
        if (! pass_stdin) {
            if (tcgetattr(fd, &termios_old)) {
                ciphart_err("failed to get terminal settings.");
                return RETURN_FAIL_IO;
            }
            termios_new = termios_old;
            termios_new.c_lflag &= ~ECHO;
            if (tcsetattr(fd, TCSAFLUSH, &termios_new)) {
                ciphart_err("failed to disable terminal echo.");
                return RETURN_FAIL_IO;
            }
        }

        /* write prompt */
        if (pass_stdin) ciphart_info(prompts[attempt]);
        else {
            write(
                fd, prompts[attempt], strlen(prompts[attempt])
            );
        }

        /* read password and hash */
        int eof = 0;
        crypto_generichash_init(state, NULL, 0, SIZE_KEY);
        while (1) {
            ssize_t len = 0;
            switch (ciphart_eof(fd, buf_pass, 1, &len)) {
                case CEOF_OK:
                    break;
                case CEOF_EOF:
                    eof = 1;
                    break;
                case CEOF_FAIL:
                    ciphart_err("failed to read password.");
                    r = RETURN_FAIL_IO;
                    goto fail;
                case CEOF_UNKNOWN:
                    ciphart_err("mystery when reading password.");
                    r = RETURN_FAIL_IO;
                    goto fail;
            }
            if (*buf_pass == '\n' || eof) break;
            crypto_generichash_update(state, buf_pass, len);
        }
        if (! pass_stdin) write(fd, "\n", 1);
        crypto_generichash_final(state, key, SIZE_KEY);

        /* repeat if confirmation is needed and keys mismatched */
        if (flags & FLAG_E && pass_confirm) {
            if (attempt == 1) {
                size_t i;
                int mismatched = 0;
                for (i = 0; i < SIZE_KEY; i++) {
                    if (key[i] != key_confirm[i]) {
                        mismatched = 1;
                        break;
                    }
                }
                if (mismatched == 0) goto success;
                ciphart_err("passwords mismatched.  retrying...");
            }
            attempt++;
            if (attempt > 1) attempt = 0;
            buf_tmp = key;
            key = key_confirm;
            key_confirm = buf_tmp;
        } else {
            goto success;
        }
    }

success:
    /* success! */
    r = RETURN_OK;
fail:
    if (! pass_stdin && tcsetattr(fd, TCSAFLUSH, &termios_old)) {
        ciphart_err("failed to re-enable terminal echo");
        r = RETURN_FAIL_IO;
    }
    if (! pass_stdin && fd != -1) close(fd);
    return r;
}

/* convert strings into numbers within range */
int ciphart_str2size_t(
    char f, const char *s, size_t min, size_t max, size_t *out
) {
    *out = 0;
    int i, num;
    for (i = 0; s[i] >= '0' && s[i] <= '9'; i++) {
        num = s[i] - '0';
        if (*out > max / 10 - num + max % 10) {
            ciphart_err("'-%c %s' is larger than maximum '%zu'", f, s, max);
            return RETURN_FAIL_ARGS;
        }
        *out *= 10;
        *out += num;
    }
    if (s[i] != '\0') {
        ciphart_err("'-%c %s' contains illegal symbol '%c'", f, s, s[i]);
        return RETURN_FAIL_ARGS;
    }
    if (*out < min) {
        ciphart_err("'-%c %s' is smaller than minimum '%zu'", f, s, min);
        return RETURN_FAIL_ARGS;
    }
    return RETURN_OK;
}

int ciphart_str2uint64_t(
    char f, const char *s, uint64_t min, uint64_t max, uint64_t *out
) {
    *out = 0;
    int i, num;
    for (i = 0; s[i] >= '0' && s[i] <= '9'; i++) {
        num = s[i] - '0';
        if (*out > max / 10 - num + max % 10) {
            ciphart_err(
                "'-%c %s' is larger than maximum '%"PRId64"'", f, s, max
            );
            return RETURN_FAIL_ARGS;
        }
        *out *= 10;
        *out += num;
    }
    if (s[i] != '\0') {
        ciphart_err("'-%c %s' contains illegal symbol '%c'", f, s, s[i]);
        return RETURN_FAIL_ARGS;
    }
    if (*out < min) {
        ciphart_err(
            "'-%c %s' is smaller than minimum '%"PRId64"'",
            f, s, min
        );
        return RETURN_FAIL_ARGS;
    }
    return RETURN_OK;
}

int ciphart_str2int(
    char f, const char *s, int min, int max, int *out
) {
    *out = 0;
    int i, num;
    for (i = 0; s[i] >= '0' && s[i] <= '9'; i++) {
        num = s[i] - '0';
        if (*out > max / 10 - num + max % 10) {
            ciphart_err("'-%c %s' is larger than maximum '%d'", f, s, max);
            return RETURN_FAIL_ARGS;
        }
        *out *= 10;
        *out += num;
    }
    if (s[i] != '\0') {
        ciphart_err("'-%c %s' contains illegal symbol '%c'", f, s, s[i]);
        return RETURN_FAIL_ARGS;
    }
    if (*out < min) {
        ciphart_err("'-%c %s' is smaller than minimum '%d'", f, s, min);
        return RETURN_FAIL_ARGS;
    }
    return RETURN_OK;
}

int ciphart_str2double(
    const char *s, double min, double max, double *out
) {
    errno = 0;
    char *end;
    double x = strtod(s, &end);
    if (errno == ERANGE) {
        ciphart_err("%s' is too big for 'double'.", s);
        return RETURN_FAIL;
    }
    *out = x;
    if (end == s || *end != '\0') {
        ciphart_err("'%s' is not a valid 'double' number.", s);
        return RETURN_FAIL;
    }
    if (*out > max || *out < min) {
        ciphart_err("'%s' is not in [%.2f, %.2f].", s, min, max);
        return RETURN_FAIL;
    }
    return RETURN_OK;
}

/* worker thread */
void *ciphart_thread(void *arg) {
    struct thread_arg *a = arg;
    uint64_t *task_id = (uint64_t *)(a->nonce) + 1;
    uint64_t *round_id = (uint64_t *)(a->nonce) + 2;
    unsigned char *buf1 = a->pad + a->first_task_id * a->task_size;
    unsigned char *buf2 = buf1 + a->task_size;
    unsigned char *buf_tmp;
    for (
        *task_id = a->first_task_id;
        *task_id < a->first_task_id + a->tasks;
        (*task_id) += 2
    ) {
        for (
            *round_id = 0;
            *round_id < a->task_rounds * 2;/* repeat twice since this
                                            * function solves 2 tasks */
            (*round_id)++
        ) {
            crypto_stream_xchacha20_xor(
                buf1, buf2, a->task_size, a->nonce, a->key
            );
            buf_tmp = buf1;
            buf1 = buf2;
            buf2 = buf_tmp;
        }
        buf1 += a->task_size * 2;
        buf2 += a->task_size * 2;
    }

    /* lock mutex to update xor */
    if (pthread_mutex_lock(a->mutex_xor)) {
        ciphart_err("failed to lock mutex_xor.");
        a->r = RETURN_FAIL_PTHREAD;
        exit(a->r);
    }

    /* update pad's xor using last bytes from the tasks */
    for (
        buf1 = a->pad + a->first_task_id * a->task_size;
        buf1 < a->pad + (a->first_task_id + a->tasks) * a->task_size;
        buf1 += a->task_size
    ) {
        *a->xor ^= *(uint64_t *)(buf1 + a->task_size - sizeof(int64_t));
    }

    /* unlock mutex */
    if (pthread_mutex_unlock(a->mutex_xor)) {
        ciphart_err("failed to unlock mutex_xor.");
        a->r = RETURN_FAIL_PTHREAD;
        exit(a->r);
    }

    pthread_exit(&a->r);
}

/* derive a more expensive key */
int ciphart_complicate(
    size_t pad_size, size_t task_size,
    uint64_t pads, uint64_t task_rounds, size_t threads,
    unsigned char *key, pthread_t *ids, struct thread_arg *a,
    unsigned char *nonces, uint64_t *xor
) {
    /* function's initial return code */
    int r = RETURN_FAIL;

    /* make xor independent of how moah gets repartitioned over the
     * releases of ciphart */
    *xor = 0;

    /* securely allocate the working pad for the tasks */
    unsigned char *pad = sodium_malloc(pad_size);
    if (pad == NULL) {
        ciphart_err("failed to allocate memory for pad.");
        return RETURN_FAIL_MEM;
    }

    /* prepare pthreads */
    pthread_mutex_t mutex_xor = PTHREAD_MUTEX_INITIALIZER;
    uint64_t tasks = pad_size / task_size;
    uint64_t task_pairs = tasks / 2;
    uint64_t task_pairs_remaining = task_pairs % threads;
    uint64_t task_pairs_per_thread = \
        (task_pairs - task_pairs_remaining) / threads;
    uint64_t first_task_id = 0;
    size_t thread;
    for (thread = 0; thread < threads; thread++) {
        a[thread].tasks = task_pairs_per_thread * 2;
        if (task_pairs_remaining) {
            a[thread].tasks += 2;
            task_pairs_remaining--;
        }
        a[thread].task_size = task_size;
        a[thread].task_rounds = task_rounds;
        a[thread].first_task_id = first_task_id;
        a[thread].pad = pad;
        a[thread].nonce = nonces + thread * SIZE_NONCE;
        a[thread].key = key;
        a[thread].xor = xor;
        a[thread].mutex_xor = &mutex_xor;
        a[thread].r = RETURN_OK;
        first_task_id += a[thread].tasks;
    }

    /* work on the pads and the tasks in them */
    uint64_t pad_id;
    unsigned char *buf;
    char time_left_desc[TIME_LEFT_DESC_SIZE];
    uint64_t ui_update = 0;
    time_t time_start = time(NULL);
    for (pad_id = 0; pad_id < pads; pad_id++) {
        for (thread = 0; thread < threads; thread++) {
            *(uint64_t *)(a[thread].nonce) = pad_id;
            a[thread].pad_id = pad_id;
            if (pthread_create(
                &ids[thread], NULL, &ciphart_thread, &a[thread]
            )) {
                ciphart_err("failed to create threads.");
                r = RETURN_FAIL_PTHREAD;
                goto fail;
            }
        }
        for (thread = 0; thread < threads; thread++) {
            int *thread_r;
            if (pthread_join(ids[thread], (void **)&thread_r)) {
                ciphart_err("failed to join thread no. %zu.", thread);
                r = RETURN_FAIL_PTHREAD;
            }
            if (r == RETURN_FAIL_PTHREAD) goto fail;
            if (*thread_r) {
                r = *thread_r;
                if (r) goto fail;
            }
        }

        /* cross-task xoring for memory hardness */
        for (
            buf = pad;
            buf < pad + pad_size;
            buf += task_size
        ) {
            *(uint64_t *)buf ^= *xor;
        }

        /* update ui to show progress */
        ui_update += tasks * task_rounds;
        if (verbose && ui_update > UI_UPDATE_THRESHOLD) {
            ui_update = 0;
            ciphart_info(
                "added %f bits worth of difficulty.  %s left...",
                log2(pad_id + 1) + log2(tasks) + log2(task_rounds),
                ciphart_oracle(
                    (pad_id + 1) * tasks * task_rounds,
                    pads * tasks * task_rounds, time_start, time_left_desc
                )
            );
        }
    }

    /* how much entropy did we actually add? */
    if (verbose)
        ciphart_info(
            "added %f bits from %" PRId64
            " pads with %" PRId64 " %"PRId64"-round tasks.",
            log2(pads) + log2(tasks) + log2(task_rounds),
            pad_id, tasks, task_rounds
        );

    /* compress whole pad into a better key */
    crypto_generichash(key, SIZE_KEY, pad, pad_size, NULL, 0);

    /* success! */
    r = RETURN_OK;
fail:
    if (pad != NULL) sodium_free(pad);
    return r;
}

/* predicts times needed to completion */
char *ciphart_oracle(
    uint64_t tasks_done, uint64_t tasks_total,
    time_t time_start, char *time_left_desc
) {
    /*
     * tasks_total   time_total
     * ----------- = ----------
     * tasks_done    time_done
     *
     * time_total = tasks_total / tasks_done * time_done
     */

    time_t time_now = time(NULL);
    time_t time_done = time_now - time_start;
    double time_total = 1.0 * tasks_total / tasks_done * time_done;
    double time_left = time_total - time_done;
    int units[] = {60, 60, 24, 30, 12, 100}, i, j;
    char *descs[] = {
        "minutes", "hours", "days", "months", "years", "centuries"
    };
    snprintf(
        time_left_desc, TIME_LEFT_DESC_SIZE, "%.0f seconds", time_left
    );
    for (i = 5; i >= 0; i--) {
        double scaled = time_left;
        for (j = 0; j <= i; j++) scaled /= units[j];
        if (scaled > 1) {
            snprintf(
                time_left_desc, TIME_LEFT_DESC_SIZE,
                "%.1f %s", scaled, descs[i]
            );
            break;
        }
    }
    return time_left_desc;
}

/* unbuffered chunk reader to detect end-of-file without an extra round
 * with zery-bytes read.  this is necessary to let libsodium's encryption
 * work peacefully, as it assumes that each encrypted chunk is of a given
 * size, except the last one.  basically this tries to feel like feof,
 * except for not using buffered i/o */
int ciphart_eof(int fd, unsigned char *buf, size_t count, ssize_t *len) {
    ssize_t in_len = read(fd, buf, count);
    if (in_len < 0) return CEOF_FAIL;
    if (in_len == 0) return CEOF_EOF;
    *len += in_len;
    if ((size_t)in_len == count) return CEOF_OK;
    if ((size_t)in_len < count)
        return ciphart_eof(fd, buf + in_len, count - in_len, len);
    return CEOF_UNKNOWN;
}

/* encrypt input into output */
int ciphart_enc(
    unsigned char *key, unsigned char *header,
    crypto_secretstream_xchacha20poly1305_state *state,
    unsigned char *buf_cleartext, unsigned char *buf_ciphertext,
    size_t chunk_clr, char *path_in, char *path_out
) {
    int r = RETURN_FAIL;
    int fd_in = -1; /* this data is unencrypted, so better be unbuffered to
                       avoid possibly getting swapped into disk */
    FILE *fp_out = NULL; /* we can use bufferd since data is encrypted */

    /* open input path for read */
    if (strcmp(path_in, "-") == 0) {
        fd_in = STDIN_FILENO;
        ciphart_info("reading input from STDIN (end by EOF)...");
    } else {
        fd_in = open(path_in, O_RDONLY);
    }
    if (fd_in == -1) {
        ciphart_err("failed to open '%s' for read.", path_in);
        return RETURN_FAIL_IO;
    }

    /* open output path for write */
    if (strcmp(path_out, "-") == 0) {
        fp_out = stdout;
    } else {
        fp_out = fopen(path_out, "w");
    }
    if (fp_out == NULL) {
        ciphart_err("failed to open '%s' for write.", path_out);
        r = RETURN_FAIL_IO;
        goto fail;
    }

    /* get header and state */
    crypto_secretstream_xchacha20poly1305_init_push(state, header, key);
    if (fwrite(header, 1, SIZE_HEADER, fp_out) != SIZE_HEADER) {
        ciphart_err("failed to fully write header to '%s'.", path_out);
        r = RETURN_FAIL_IO;
        goto fail;
    }

    /* encrypt */
    ssize_t in_len;
    unsigned long long out_len;
    unsigned char tag = 0;
    do {
        in_len = 0;
        switch (ciphart_eof(fd_in, buf_cleartext, chunk_clr, &in_len)) {
            case CEOF_OK:
                break;
            case CEOF_EOF:
                tag = crypto_secretstream_xchacha20poly1305_TAG_FINAL;
                break;
            case CEOF_FAIL:
                ciphart_err("failed to read input '%s'.", path_in);
                r = RETURN_FAIL_IO;
                goto fail;
            case CEOF_UNKNOWN:
                ciphart_err("mystery when reading input '%s'.", path_in);
                r = RETURN_FAIL_IO;
                goto fail;
        }
        crypto_secretstream_xchacha20poly1305_push(
            state, buf_ciphertext, &out_len, buf_cleartext, in_len,
            NULL, 0, tag
        );
        if (
            fwrite(buf_ciphertext, 1, (size_t)out_len, fp_out) != out_len
        ) {
            ciphart_err("failed to fully write to '%s'", path_out);
            r = RETURN_FAIL_IO;
            goto fail;
        }
    } while (! tag);

    /* success! */
    r = RETURN_OK;
fail:
    if (fd_in != -1 && strcmp(path_in, "-") && close(fd_in))
        ciphart_err("failed to close '%s'.", path_in);
    if (fp_out != NULL && strcmp(path_out, "-") && fclose(fp_out))
        ciphart_err("failed to close '%s'.", path_out);
    return r;
}

/* decrypt input into output */
int ciphart_dec(
    unsigned char *key, unsigned char *header,
    crypto_secretstream_xchacha20poly1305_state *state,
    unsigned char *buf_ciphertext, unsigned char *buf_cleartext,
    size_t chunk_enc, char *path_in, char *path_out
) {
    int r = RETURN_FAIL;
    FILE *fp_in = NULL; /* we can use bufferd since data is encrypted */
    int fd_out = -1; /* this data is unencrypted, so better be unbuffered
                        to avoid possibly getting swapped into disk */

    /* open input path for read */
    if (strcmp(path_in, "-") == 0) {
        fp_in = stdin;
        ciphart_info("reading input from STDIN (end by EOF)...");
    } else {
        fp_in = fopen(path_in, "r");
    }
    if (fp_in == NULL) {
        ciphart_err("failed to open '%s' for read.", path_in);
        return RETURN_FAIL_IO;
    }

    /* get header and state */
    size_t r_fread = fread(header, 1, SIZE_HEADER, fp_in);
    int r_init = crypto_secretstream_xchacha20poly1305_init_pull(
        state, header, key
    );
    if (r_fread != SIZE_HEADER || r_init != 0) {
        ciphart_err("incomplete header.");
        r = RETURN_FAIL_BADEND;
        goto fail;
    }

    /* open output path for write */
    if (strcmp(path_out, "-") == 0) {
        fd_out = STDOUT_FILENO;
    } else {
        fd_out = open(
            path_out, O_WRONLY | O_CREAT | O_TRUNC, FILE_MODE_PLAIN
        );
    }
    if (fd_out == -1) {
        ciphart_err("failed to open '%s' for write.", path_out);
        r = RETURN_FAIL_IO;
        goto fail;
    }

    /* decrypt */
    size_t in_len;
    ssize_t r_write;
    int eof;
    unsigned long long out_len;
    unsigned char tag;
    do {
        in_len = fread(buf_ciphertext, 1, chunk_enc, fp_in);
        eof = feof(fp_in);
        if (
            crypto_secretstream_xchacha20poly1305_pull(
                state, buf_cleartext, &out_len, &tag, buf_ciphertext,
                in_len, NULL, 0
            ) != 0
        ) {
            ciphart_err("incorrect password or corrupted input.");
            r = RETURN_FAIL_BADPASS;
            goto fail;
        }
        if (
            tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL
            && ! eof
        ) {
            ciphart_err("premature end of input '%s'.", path_in);
            r = RETURN_FAIL_BADEND;
            goto fail;
        }
        r_write = write(fd_out, buf_cleartext, (size_t)out_len);
        if (r_write < 0) {
            ciphart_err("failed to write to '%s'", path_out);
            r = RETURN_FAIL_IO;
            goto fail;
        }
        if ((unsigned long long)r_write != out_len) {
            ciphart_err("failed to fully write to '%s'", path_out);
            r = RETURN_FAIL_IO;
            goto fail;
        }
    } while (! eof);

    /* success! */
    r = RETURN_OK;
fail:
    if (fp_in != NULL && strcmp(path_in, "-") && fclose(fp_in))
        ciphart_err("failed to close '%s'.", path_in);
    if (fd_out != -1 && strcmp(path_out, "-") && close(fd_out))
        ciphart_err("failed to close '%s'.", path_out);
    return r;
}
