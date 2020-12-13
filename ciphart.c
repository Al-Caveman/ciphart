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
#include <math.h>       /* pow, log2 */
#include <pthread.h>    /* pthread_* */
#include <sodium.h>     /* crypto_*, sodium_* */
#include <stdarg.h>     /* va_* */
#include <stdint.h>     /* uint64_t, uint32_t */
#include <stdio.h>      /* printf, fprintf, vfprintf, va_*, freadf, feof,
                            rewind, fputs */
#include <stdlib.h>     /* strtoull, strtod, exit */
#include <string.h>     /* strcmp */
#include <sys/stat.h>   /* open */
#include <sys/types.h>  /* open */
#include <termios.h>    /* tcgetattr, tcsetattr */
#include <time.h>       /* time */
#include <unistd.h>     /* getopt, isatty, STDOUT_FILENO, STDERR_FILENO,
                            tcgetattr, tcsetattr, write  */

#define APP_NAME "ciphart"
#define APP_VERSION "3.1.1"
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
#define DFLT_PAD_SIZE 999997440lu /* bytes for the whole memory pad */
#define DFLT_TASK_SIZE 4096lu /* bytes per task in the memory pad */
#define DFLT_TASK_ROUNDS 1llu /* rounds per task */
#define DFLT_ENTRPY 20.0
#define DFLT_THREADS 4 /* number of threads */
#define ENTRPY_MAX 64.0
#define COLOR_HEADING "\033[1;37m"
#define COLOR_NOTE "\033[0;90m"
#define COLOR_BAR "\033[1;90m"
#define COLOR_BANNER "\033[0;90m"
#define COLOR_ERR "\033[1;31m"
#define COLOR_WARN "\033[1;33m"
#define COLOR_INFO "\033[1;32m"
#define COLOR_PROMPT "\033[1;34m"
#define COLOR_PROMPT_TEXT "\033[0;34m"
#define COLOR_RESET "\033[0m"
#define PRETTY_AUTO     "auto"
#define PRETTY_ALWAYS   "always"
#define PRETTY_NEVER    "never"
#define UI_UPDATE_THRESHOLD 100000llu
#define FLAG_E  1
#define FLAG_D  2
#define FLAG_K  4
#define FLAG_W  8
#define FLAG_C  16
#define FLAG_H  32
#define FLAG_S  64
#define FLAG_Z  128
#define FLAG_I  256
#define FLAG_O  512
#define FLAG_M  1024
#define FLAG_T  2048
#define FLAG_R  4096
#define FLAG_N  8192
#define FLAG_J  16384
#define FLAG_P  32768
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

/* 1 = colors displayed, 0 not */
int pretty_stdout = 0, pretty_stderr = 0;

/* print error */
void ciphart_err(const char *fmt, ...);

/* print warning */
void ciphart_warn(const char *fmt, ...);

/* print info */
void ciphart_info(const char *fmt, ...);

/* print prompt */
void ciphart_prompt(const char *fmt, ...);

/* print status bar */
void ciphart_bar(const char *fmt, ...);

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
    double *entropy, size_t *threads
);

/* obtain key from password from STDIN */
int ciphart_get_key(
    int flags,
    unsigned char *buf_pass, unsigned char *key,
    unsigned char *key_confirm, int pass_stdin, int pass_confirm
);

/* convert strings into numbers within range */
int ciphart_str2size_t(
    const char *s, size_t min, size_t max, size_t *out);
int ciphart_str2uint64_t(
    const char *s, uint64_t min, uint64_t max, uint64_t *out);
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
int ciphart_complicate (
    double entropy, size_t pad_size, size_t task_size,
    uint64_t task_rounds, size_t threads,
    unsigned char *key, pthread_t *ids,
    struct thread_arg *a,
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
    unsigned char *buf_cleartext, unsigned char *buf_ciphertext,
    size_t chunk_clr, char *path_in, char *path_out
);

/* decrypt input into output */
int ciphart_dec(
    unsigned char *key, unsigned char *header,
    unsigned char *buf_ciphertext, unsigned char *buf_cleartext,
    size_t chunk_enc, char *path_in, char *path_out
);

int main(int argc, char **argv) {
    int r = RETURN_FAIL;
    int fd_kdf = -1;
    void *moah = NULL;
    char *exec_name = argv[0];

    /* assign default values */
    if (isatty(STDOUT_FILENO)) pretty_stdout = 1;
    if (isatty(STDERR_FILENO)) pretty_stderr = 1;
    int pass_stdin = 0;
    int pass_confirm = 1;
    char *path_in = DFLT_PATH_IN;
    char *path_out = DFLT_PATH_OUT;
    size_t pad_size = DFLT_PAD_SIZE;
    size_t task_size = DFLT_TASK_SIZE;
    uint64_t task_rounds = DFLT_TASK_ROUNDS;
    double entropy = DFLT_ENTRPY;
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

    /* show banner */
    ciphart_banner(exec_name);

    /* define action description, and do the easy actions */
    const char *act_desc = "";
    if (flags & FLAG_E && flags & FLAG_K) {
        act_desc = "derive a better key, then encrypt with it";
    } else if (flags & FLAG_D && flags & FLAG_K) {
        act_desc = "derive a better key, then decrypt with it";
    } else if (flags & FLAG_E) {
        act_desc = "only encrypt, without deriving a better key";
    } else if (flags & FLAG_D) {
        act_desc = "only decrypt, without deriving a better key";
    } else if (flags & FLAG_K) {
        act_desc = "only derive a better key, then exit";
        ciphart_warn(
            "note: entropy is calculated based on:\n\n"
            "       - encryption/decryption using xchacha20.\n"
            "       - %llu bytes key size.\n"
            "       - %llu chunk size (set by '-t').\n\n"

            "    while using other methods will still limit risk of\n"
            "    brute-forcing, the meaning of the calculated entropy\n"
            "    bits won't be guaranteed to be true.\n\n"

            "    this is not an algorithmic limitation, but purely an\n"
            "    implementation one as i didn't find a need to support\n"
            "    other methods than the one stated above.\n",
        SIZE_KEY, task_size);
    } else if (flags & FLAG_W) {
        ciphart_fputs(WARRANTY);
        return RETURN_OK;
    } else if (flags & FLAG_C) {
        ciphart_fputs(CONDITIONS);
        return RETURN_OK;
    } else if (flags & FLAG_H) {
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
     * the cross-tax xor-ing happens (to introduce memory hardness).
     *
     * this is a simplified version of the following:
     *      pow(2, entropy) < 2.0 * pad_size / ask_size * task_rounds
     * except for being in log form (in order to avoid memory overflows) */
    if (entropy < log2(2.0) + log2(pad_size) - log2(task_size) \
                  + log2(task_rounds)
    ) {
        ciphart_warn(
            "'-n %.2lf' is too small for '-m %zu -t %zu -r %llu'.",
            entropy, pad_size, task_size, task_rounds
        );
        entropy = log2(2.0) + log2(pad_size) - log2(task_size) + \
                  log2(task_rounds);
        ciphart_warn("using '-n %.2lf' instead...", entropy);
    }

    /* print settings' summary */
    char *color = "", *color_reset = "";
    if (pretty_stderr) {
        color = COLOR_NOTE;
        color_reset = COLOR_RESET;
    }
    ciphart_info("action:  %s.", act_desc);
    if (flags & FLAG_K) {
        ciphart_info(
            "summary of parameters of the key drivation function:\n"
            "    -m%10zu"   "  %s# pad's memory size.%s\n"
            "    -t%10zd"   "  %s# tasks' size in the pad.%s\n"
            "    -r%10llu"  "  %s# rounds per task.%s\n"
            "    -n%10.6lf" "  %s# entropy-worth difficulty to add.%s",
            pad_size,    color, color_reset,
            task_size,   color, color_reset,
            task_rounds, color, color_reset,
            entropy,     color, color_reset
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
     * key----------------------------------*               buf_cleartext
     * key_confirm*     ids---*             header*         buf_ciphertext
     * buf_pass---*     args--*
     *                  nonces*
     *                  xor---*
     */
    size_t moah_phases[4];
    moah_phases[0] = SIZE_KEY + SIZE_KEY + 1;
    moah_phases[1] = SIZE_KEY                              \
                     + threads * sizeof(pthread_t)         \
                     + threads * sizeof(struct thread_arg) \
                     + threads * SIZE_NONCE                \
                     + sizeof(uint64_t);
    moah_phases[2] = SIZE_KEY + SIZE_HEADER;
    moah_phases[3] = chunk_clr + chunk_enc;
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
    unsigned char *key = moah; /* phase 0 */
    unsigned char *key_confirm  = key + SIZE_KEY;
    unsigned char *buf_pass = key_confirm + 1;
    pthread_t *ids = (void *)key_confirm; /* phase 1 */
    struct thread_arg *args = (void *)(ids  + threads);
    unsigned char *nonces = (void *)(args  + threads);
    uint64_t *xor = (uint64_t *)(nonces + threads * SIZE_NONCE);
    unsigned char *header = key_confirm; /* phase 2 */
    unsigned char *buf_cleartext = moah; /* phase 3 */
    unsigned char *buf_ciphertext = buf_cleartext + chunk_clr;

    /* get key */
    int key_r = ciphart_get_key(
        flags, buf_pass, key, key_confirm, pass_stdin, pass_confirm
    );
    if (key_r) {
        r = key_r;
        goto fail;
    }

    /* derive a more expensive key that's worth 'entropy' bits */
    if (flags & FLAG_K) {
        ciphart_info(
            "deriving a better key worth ~%.2f more entropy bits...",
            entropy
        );
        int kdf_r = ciphart_complicate(
                entropy, pad_size, task_size, task_rounds, threads,
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
        ciphart_info("encrypting '%s' into '%s'...", path_in, path_out);
        int r_enc = ciphart_enc(
            key, header, buf_cleartext, buf_ciphertext,
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
        ciphart_info("decrypting '%s' into '%s'...", path_in, path_out);
        int r_dec = ciphart_dec(
            key, header, buf_ciphertext, buf_cleartext,
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
    char *color = "", *color_reset = "";
    if (pretty_stderr) {
        color = COLOR_ERR;
        color_reset = COLOR_RESET;
    }
    fprintf(stderr,"%s!!!%s ", color , color_reset);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr,"\n");
}

/* print warning */
void ciphart_warn(const char *fmt, ...) {
    char *color = "", *color_reset = "";
    if (pretty_stderr) {
        color = COLOR_WARN;
        color_reset = COLOR_RESET;
    }
    fprintf(stderr,"%s***%s ", color, color_reset);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr,"\n");
}

/* print info */
void ciphart_info(const char *fmt, ...) {
    char *color = "", *color_reset = "";
    if (pretty_stderr) {
        color = COLOR_INFO;
        color_reset = COLOR_RESET;
    }
    fprintf(stderr,"%s>>>%s ", color, color_reset);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr,"\n");
}

/* print prompt */
void ciphart_prompt(const char *fmt, ...) {
    char *color = "", *color_text = "", *color_reset = "";
    if (pretty_stderr) {
        color = COLOR_PROMPT;
        color_text = COLOR_PROMPT_TEXT;
        color_reset = COLOR_RESET;
    }
    fprintf(stderr,"%s<<<%s ", color, color_text);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr,"%s", color_reset);
}

/* print status bar */
void ciphart_bar(const char *fmt, ...) {
    char *color = "", *color_reset = "";
    if (pretty_stderr) {
        color = COLOR_BAR;
        color_reset = COLOR_RESET;
    }
    fprintf(stderr,"\r%s>>>%s ", color, color_reset);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

/* print banner */
void ciphart_banner(char *exec_name) {
    char *color = "", *color_reset = "";
    if (pretty_stderr) {
        color = COLOR_BANNER;
        color_reset = COLOR_RESET;
    }
    fprintf(
        stderr,
        "%s%s v%s  copyright (C) %s  caveman\n"
        "%s\n\n"
        "this program comes with ABSOLUTELY NO WARRANTY; for details\n"
        "type `%s -w'.  this is free software, and you are welcome to\n"
        "redistribute it under certain conditions; type `%s -c' for\n"
        "details.%s\n\n",
        color, APP_NAME, APP_VERSION, APP_YEAR, APP_URL, exec_name,
        exec_name, color_reset
    );
}

/* print help */
void ciphart_help(char *exec_name) {
    char *color = "", *color_reset = "";
    if (pretty_stdout) {
        color = COLOR_HEADING;
        color_reset = COLOR_RESET;
    }
    fprintf(
        stdout,
        "%sSYNOPSIS%s\n"
        " %s -e       [-s] [-z] [-i PATH] [-o PATH] [-p COLOR]\n"
        " %s -d       [-s]      [-i PATH] [-o PATH] [-p COLOR]\n"
        " %s -k       [-s]                [-o PATH] [-p COLOR] [KDF ...]\n"
        " %s -ek      [-s] [-z] [-i PATH] [-o PATH] [-p COLOR] [KDF ...]\n"
        " %s -dk      [-s]      [-i PATH] [-o PATH] [-p COLOR] [KDF ...]\n"
        " %s -{w,c,h}                               [-p COLOR]\n\n"

        "%sACTIONS%s\n"
        " -e        only encrypt input plaintext into output ciphertext.\n"
        " -d        only decrypt input ciphertext into output plaintext.\n"
        " -k        only derive a more secure key.\n"
        " -ek       equals '-e', but also derives a more secure key.\n"
        " -dk       equals '-d', but also derives a more secure key.\n"
        " -w        show warranty notice.\n"
        " -c        show usage conditions.\n"
        " -h        show this help.\n\n"

        "%sOPTIONS%s\n"
        " -s        read passwords via STDIN.\n"
        " -z        disable password confirmation.\n"
        " -i PATH   path to input file.  default is '-' for STDIN.\n"
        " -o PATH   path to output file.  default is '-' for STDOUT.\n"
        " -p COLOR  when to show pretty colors.  default is '%s'.\n\n"

        "%sKDF%s\n"
        " -m INT    size of memory pad.  default is '%lu'.\n"
        " -t INT    bytes of each task in the pad.  default is '%lu'.\n"
        " -r INT    repetition in each task.  default is '%llu'.\n"
        " -n REAL   entropy bits.  default is '%.2f'.\n"
        " -j INT    number of concurrent threads.  default is '%d'.\n\n"

        "%sVALUES%s\n"
        " PATH      file path.  '-' means STDIN or STDOUT.\n"
        " INT       positive integer.\n"
        " REAL      positive real number.\n"
        " COLOR     one of:  '%s', '%s' or '%s'.\n\n"

        "%sRETURN CODES%s\n"
        " %d         success.\n"
        " %d         general failure.\n"
        " %d         libsodium failure.\n"
        " %d         argument parsing failure.\n"
        " %d         io failure.\n"
        " %d         memory allocation failure.\n"
        " %d         pthread feailure.\n"
        " %d         bad password or corrupted input.\n"
        " %d         premature input end.\n",
        color, color_reset, /* synopsis */
        exec_name, exec_name, exec_name, exec_name, exec_name, exec_name,
        color, color_reset, /* actions */
        color, color_reset, /* options */
        PRETTY_AUTO,
        color, color_reset, /* kdf */
        DFLT_PAD_SIZE, DFLT_TASK_SIZE, DFLT_TASK_ROUNDS, DFLT_ENTRPY,
        DFLT_THREADS,
        color, color_reset, /* values */
        PRETTY_AUTO, PRETTY_ALWAYS, PRETTY_NEVER,
        color, color_reset, /* return codes */
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
    double *entropy, size_t *threads
) {
    int arg_parse_err = ARG_PARSE_OK, opt;
    while ((opt = getopt(
        argc, argv, "-:eEdDkKwchi:o:m:t:r:n:j:p:sz"
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
                    optarg, sizeof(uint64_t) * 2, SIZE_MAX, pad_size
                )) arg_parse_err = ARG_PARSE_ERR;
                *flags |= FLAG_M;
                break;
            case 't': /* size of each task in the pad */
                if (ciphart_str2size_t(
                    optarg, sizeof(uint64_t), SIZE_MAX / 2, task_size
                )) arg_parse_err = ARG_PARSE_ERR;
                *flags |= FLAG_T;
                break;
            case 'r': /* rounds in each task */
                if (ciphart_str2uint64_t(
                    optarg, 1, UINT64_MAX / 2, task_rounds
                )) arg_parse_err = ARG_PARSE_ERR;
                *flags |= FLAG_R;
                break;
            case 'n': /* entropy bits */
                if (ciphart_str2double(
                    optarg, 0, 63, entropy
                )) arg_parse_err = ARG_PARSE_ERR;
                *flags |= FLAG_N;
                break;
            case 'j': /* number of concurrent threads */
                if (ciphart_str2size_t(
                    optarg, 1, SIZE_MAX / sizeof(struct thread_arg),
                    threads
                )) arg_parse_err = ARG_PARSE_ERR;
                *flags |= FLAG_J;
                break;
            case 'p': /* pretty colors mode */
                if (strcmp(optarg, PRETTY_AUTO) == 0) {
                    /* disable colors for when stdout/stderr is not a
                     * terminal.  this is already done earlier, so no need
                     * to do it here again */
                } else if (strcmp(optarg, PRETTY_ALWAYS) == 0) {
                    pretty_stdout = 1;
                    pretty_stderr = 1;
                } else if (strcmp(optarg, PRETTY_NEVER) == 0) {
                    pretty_stdout = 0;
                    pretty_stderr = 0;
                } else {
                    ciphart_err("'%s' is invalid color mode.", optarg);
                }
                *flags |= FLAG_P;
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
            "option '-z' is valid only with '-e' or '-ek'.");
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
    unsigned char *key_confirm, int pass_stdin, int pass_confirm
) {
    int r = RETURN_FAIL;

    /* should password be taken from /dev/tty?  or stdin? */
    int fd;
    char *prompts[2];
    if (pass_stdin) {
        fd = STDIN_FILENO;
        prompts[0] = "reading password from STDIN (end by EOF): ";
        prompts[1] = "confirming password from STDIN (end by EOF): ";
    } else {
        fd = open(DEV_TTY, O_RDONLY);
        prompts[0] = "password: ";
        prompts[1] = "confirming password: ";
        if (fd == -1) {
            ciphart_err("failed to open '%s' for read.", DEV_TTY);
            r = RETURN_FAIL_IO;
            goto fail;
        }
    }

    /* disable terminal echo */
    struct termios termios_old, termios_new;
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

    /* obtain password */
    unsigned char attempt = 0;
    unsigned char *buf_tmp;
    while (1) {
        ciphart_prompt(prompts[attempt % 2]);

        /* read password and hash */
        crypto_generichash_state state;
        ssize_t len;
        crypto_generichash_init(&state, NULL, 0, SIZE_KEY);
        while ((len = read(fd, buf_pass, 1)) > 0) {
            if (! pass_stdin && buf_pass[0] == '\n') {
                break;
            } else {
                crypto_generichash_update(&state, buf_pass, len);
            }
        }
        fprintf(stderr, "\n");
        crypto_generichash_final(&state, key, SIZE_KEY);

        /* repeat if confirmation is needed and keys mismatched */
        if (flags & FLAG_E && pass_confirm) {
            if (attempt % 2) {
                size_t i;
                int mismatched = 0;
                for (i = 0; i < SIZE_KEY; i++) {
                    if (key[i] != key_confirm[i]) {
                        mismatched = 1;
                        break;
                    }
                }
                if (mismatched == 0) {
                    goto success;
                } else {
                    ciphart_err("passwords mismatched.  retrying...");
                }
            }
            attempt++;
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
    const char *s, size_t min, size_t max, size_t *out
) {
    errno = 0;
    char *end;
    unsigned long long x = strtoull(s, &end, 10);
    if (x > SIZE_MAX || errno == ERANGE) {
        ciphart_err("%s' is too big for 'size_t'.", s);
        return RETURN_FAIL;
    }
    *out = x;
    if (end == s || *end != '\0') {
        ciphart_err("'%s' is not a valid 'size_t' number.", s);
        return RETURN_FAIL;
    }
    if (*out > max || *out < min) {
        ciphart_err("'%s' is not in [%zu, %zu].", s, min, max);
        return RETURN_FAIL;
    }
    return RETURN_OK;
}

int ciphart_str2uint64_t(
    const char *s, uint64_t min, uint64_t max, uint64_t *out
) {
    errno = 0;
    char *end;
    unsigned long long x = strtoull(s, &end, 10);
    if (x > UINT64_MAX || errno == ERANGE) {
        ciphart_err("%s' is too big for 'uint64_t'.", s);
        return RETURN_FAIL;
    }
    *out = x;
    if (end == s || *end != '\0') {
        ciphart_err("'%s' is not a valid 'uint64_t' number.", s);
        return RETURN_FAIL;
    }
    if (*out > max || *out < min) {
        ciphart_err("'%s' is not in [%llu, %llu].", s, min, max);
        return RETURN_FAIL;
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
    uint64_t *round_id = (uint64_t *)(a->nonce) + 2;
    unsigned char *buf1 = a->pad + a->first_task_id * a->task_size;
    unsigned char *buf2 = buf1 + a->task_size;
    unsigned char *buf_tmp;
    uint64_t task_id;
    for (
        task_id = a->first_task_id;
        task_id < a->first_task_id + a->tasks;
        task_id += 2
    ) {
        *(a->nonce + 1) = task_id;
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
int ciphart_complicate (
    double entropy, size_t pad_size, size_t task_size,
    uint64_t task_rounds, size_t threads,
    unsigned char *key, pthread_t *ids,
    struct thread_arg *a,
    unsigned char *nonces, uint64_t *xor
) {
    /* function's initial return code */
    int r = RETURN_FAIL;

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
    uint64_t pads = pow(2, entropy) / tasks / task_rounds + 0.999;
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
        if (ui_update > UI_UPDATE_THRESHOLD) {
            ui_update = 0;
            ciphart_bar(
                "added %f bits worth of difficulty.  %s left...",
                log2((pad_id + 1) * tasks * task_rounds),
                ciphart_oracle(
                    (pad_id + 1) * tasks * task_rounds,
                    pads * tasks * task_rounds, time_start, time_left_desc
                )
            );
        }
    }

    /* how much entropy did we actually add? */
    fprintf(stderr, "\r");
    ciphart_info(
        "added %f bits from %llu pads containing %llu %llu-round tasks.",
        log2((pad_id + 1) * tasks * task_rounds),
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
char *ciphart_oracle (
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
    crypto_secretstream_xchacha20poly1305_state state;
    crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);
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
            &state, buf_ciphertext, &out_len, buf_cleartext, in_len,
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
    } else {
        fp_in = fopen(path_in, "r");
    }
    if (fp_in == NULL) {
        ciphart_err("failed to open '%s' for read.", path_in);
        return RETURN_FAIL_IO;
    }

    /* get header and state */
    crypto_secretstream_xchacha20poly1305_state state;
    size_t r_fread = fread(header, 1, SIZE_HEADER, fp_in);
    int r_init = crypto_secretstream_xchacha20poly1305_init_pull(
        &state, header, key
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
                &state, buf_cleartext, &out_len, &tag, buf_ciphertext,
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
        } else if ((unsigned long long)r_write != out_len) {
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
