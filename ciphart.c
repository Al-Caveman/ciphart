/*
 *  ciphart - XChacha20 file encrypt/decrypt.
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

#include <stdio.h> /* printf, fprintf, vfprintf, va_*, freadf, feof,
                      rewind, fputs */
#include <string.h> /* strcmp, memcpy */
#include <stdarg.h> /* va_* */
#include <sodium.h> /* crypto_*, sodium_* */
#include <limits.h> /* CHAR_BIT */
#include <stdlib.h> /* strtol */
#include <errno.h> /* errno */
#include <time.h> /* time */
#include "license.h" /* WARRANTY, CONDITIONS */

#define APP_NAME "ciphart"
#define APP_VERSION "0.0.0a"
#define APP_YEAR "2020"
#define APP_URL "https://github.com/Al-Caveman/ciphart"
#define CMD_ENC 0
#define CMD_DEC 1
#define ARG_PARSE_OK 0
#define ARG_PARSE_ERR 1
#define CHUNK_PASS 4096
#define CHUNK_CLR 4096
#define CHUNK_ENC (CHUNK_CLR+crypto_secretstream_xchacha20poly1305_ABYTES)
#define SIZE_HEADER crypto_secretstream_xchacha20poly1305_HEADERBYTES
#define SIZE_KEY crypto_secretstream_xchacha20poly1305_KEYBYTES
#define BITS_KEY (SIZE_KEY*CHAR_BIT)
#define DEFAULT_ENTROPY 17
#define BITS_ENTROPY (long int)(sizeof(unsigned long long)*CHAR_BIT)
#define COLOR_BANNER "\033[0;90m"
#define COLOR_ERR "\033[1;31m"
#define COLOR_INFO "\033[0;32m"
#define COLOR_RESET "\033[0m"
#define UI_UPDATE 1000000

/* print error */
void ciphart_err(const char *fmt, ...);

/* print info */
void ciphart_info(const char *fmt, ...);

/* print banner */
void ciphart_banner(char *exec_name);

/* print help */
void ciphart_help(char *exec_name);

/* fputs */
int ciphart_fputs(const char *s);

/* free heaps */
void ciphart_free(
    unsigned char *h1, unsigned char *h2, unsigned char *h3,
    unsigned char *h4, unsigned char *h5, FILE *fp1, FILE *fp2 
);

/* obtain key from password from STDIN */
void ciphart_get_key(unsigned char *key);

/* exponentiation function */
unsigned long long cipher_pow(long entropy);

int main(int argc, char **argv) {
    /* initialise libsodium */
    char *exec_name = argv[0];
    ciphart_banner(exec_name);
    if (sodium_init() != 0) {
        ciphart_err("failed to initialise libsodium");
        return 1;
    }

    /* parse arguments */
    int arg_parse_err = ARG_PARSE_OK;
    int cmd;
    char *path_in, *path_out;
    long entropy = DEFAULT_ENTROPY;
    char *last;
    switch (argc) {
        case 2:
            switch (argv[1][0]) {
                case 'w': return ciphart_fputs(WARRANTY);
                case 'c': return ciphart_fputs(CONDITIONS);
                case 'h': ciphart_help(exec_name); return 0;
                default:
                    ciphart_err("unknown command '%s'\n", argv[1]);
                    arg_parse_err = ARG_PARSE_ERR;
            }
            break;
        case 5:
            entropy = strtol(argv[4], &last, 10);
            if (*last != '\0') {
                ciphart_err("entropy '%s' is invalid\n", argv[4]);
                arg_parse_err = ARG_PARSE_ERR;
            }
            if (entropy < 0 || entropy > BITS_ENTROPY) {
                ciphart_err(
                    "entropy '%ld' is not in [0, %d]\n",
                    entropy, BITS_ENTROPY
                );
                arg_parse_err = ARG_PARSE_ERR;
            }
            /* FALLTHRU */
        case 4:
            path_in = argv[2];
            path_out = argv[3];
            switch (argv[1][0]) {
                case 'e': cmd = CMD_ENC; break;
                case 'd': cmd = CMD_DEC; break;
                default:
                    ciphart_err("unknown command '%s'\n", argv[1]);
                    arg_parse_err = ARG_PARSE_ERR;
            }
            break;
        default:
            ciphart_err("wrong number of arguments\n");
            arg_parse_err = ARG_PARSE_ERR;
    }
    if (arg_parse_err != ARG_PARSE_OK) {
        ciphart_help(exec_name);
        return 1;
    }

    /* allocate heaps */
    unsigned char *buf_cleartext = sodium_malloc(CHUNK_CLR);
    unsigned char *buf_ciphertext = sodium_malloc(CHUNK_ENC);
    unsigned char *buf_entropy = sodium_malloc(CHUNK_ENC);
    unsigned char *header = sodium_malloc(SIZE_HEADER);
    unsigned char *key = sodium_malloc(SIZE_KEY);
    if (
        buf_cleartext == NULL
        || buf_ciphertext == NULL
        || header == NULL
        || key == NULL
    ) {
        ciphart_err("failed to allocate memory");
        ciphart_free(
            buf_cleartext,
            buf_ciphertext,
            buf_entropy,
            header, key,
            NULL, NULL
        );
        return 1;
    }

    /* get key */
    ciphart_get_key(key);

    /* open input file */
    FILE *fp_in;
    if (strcmp(path_in, "-") == 0) {
        fp_in = stdin;
    } else {
        fp_in = fopen(path_in, "rb");
    }
    if (fp_in == NULL) {
        ciphart_err("failed to open input file '%s'", path_in);
        ciphart_free(
            buf_cleartext,
            buf_ciphertext,
            buf_entropy,
            header, key,
            NULL, NULL
        );
        return 1;
    }

    /* get header and state */
    crypto_secretstream_xchacha20poly1305_state state;
    if (cmd == CMD_ENC) {
        crypto_secretstream_xchacha20poly1305_init_push(
            &state, header, key
        );
    } else {
        ciphart_info("reading input's header...");
        size_t rfread = fread(header, 1, SIZE_HEADER, fp_in);
        int rinit = crypto_secretstream_xchacha20poly1305_init_pull(
            &state, header, key
        );
        if (rfread != SIZE_HEADER || rinit != 0) {
            ciphart_err("incomplete header");
            ciphart_free(
                buf_cleartext,
                buf_ciphertext,
                buf_entropy,
                header, key,
                fp_in, NULL
            );
            return 1;
        }
    }

    /* derive a more expensive key, such that it has the effect of adding
     * 'entropy' bits to the key */
    ciphart_info(
        "as-if-injecting %ld entropy bits into password...",
        entropy
    );
    unsigned char *buf_tmp;
    unsigned long long ent_len;
    unsigned long long i = 0, max = cipher_pow(entropy) - 1;
    size_t min_size = ((sizeof i) < (CHUNK_ENC)) ? (i) : (CHUNK_ENC);
    time_t t_start = time(NULL), t_left, t_last = 0, t_scaled;
    const char *t_unit;
    for (i = 0; i < max; i++) {
        memcpy(buf_entropy, &i, min_size);
        crypto_secretstream_xchacha20poly1305_push(
            &state, buf_ciphertext, &ent_len, buf_entropy, CHUNK_CLR,
            NULL, 0, 0
        );
        buf_tmp = buf_ciphertext;
        buf_ciphertext = buf_entropy;
        buf_entropy = buf_tmp;
        if (i != 0 && (i % UI_UPDATE) == 0) {
            t_left = (max - i) / (i / (time(NULL) - t_start));
            if (t_left/60/60/24/30/12/100/1000) {
                t_scaled = t_left/60/60/24/30/12/100/1000;
                t_unit = "hundred thousand years";
            } else if (t_left/60/60/24/30/12/100) {
                t_scaled = t_left/60/60/24/30/12/100;
                t_unit = "centuries";
            } else if (t_left/60/60/24/30/12) {
                t_scaled = t_left/60/60/24/30/12;
                t_unit = "years";
            } else if (t_left/60/60/24/30) {
                t_scaled = t_left/60/60/24/30;
                t_unit = "months";
            } else if (t_left/60/60/24) {
                t_scaled = t_left/60/60/24;
                t_unit = "days";
            } else if (t_left/60/60) {
                t_scaled = t_left/60/60;
                t_unit = "hours";
            } else if (t_left/60) {
                t_scaled = t_left/60;
                t_unit = "minutes";
            } else {
                t_scaled = t_left;
                t_unit = "seconds";
            }
            if (t_scaled - t_last) {
                ciphart_info("approx. %ld %s left...", t_scaled, t_unit);
                t_last = t_scaled;
            }
        }
    }
    memcpy(key, buf_ciphertext, SIZE_KEY);

    /* open output file */
    FILE *fp_out;
    if (strcmp(path_out, "-") == 0) {
        fp_out = stdout;
    } else {
        fp_out = fopen(path_out, "wb");
    }
    if (fp_out == NULL) {
        ciphart_err("failed to open output file '%s'", path_out);
        ciphart_free(
            buf_cleartext,
            buf_ciphertext,
            buf_entropy,
            header, key,
            fp_in, NULL
        );
        return 1;
    }

    /* encrypt/decrypt input */
    size_t in_len;
    int eof;
    unsigned long long out_len;
    unsigned char  tag;
    if (cmd == CMD_ENC) {
        ciphart_info("encrypting '%s' into '%s'...", path_in, path_out);
        fwrite(header, 1, SIZE_HEADER, fp_out);
        do {
            in_len = fread(buf_cleartext, 1, CHUNK_CLR, fp_in);
            eof = feof(fp_in);
            tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
            crypto_secretstream_xchacha20poly1305_push(
                &state, buf_ciphertext, &out_len, buf_cleartext, in_len,
                NULL, 0, tag
            );
            fwrite(buf_ciphertext, 1, (size_t) out_len, fp_out);
        } while (! eof);
    } else {
        ciphart_info("decrypting '%s' into '%s'...", path_in, path_out);
        do {
            in_len = fread(buf_ciphertext, 1, CHUNK_ENC, fp_in);
            eof = feof(fp_in);
            if (
                crypto_secretstream_xchacha20poly1305_pull(
                    &state, buf_cleartext, &out_len, &tag, buf_ciphertext,
                    in_len, NULL, 0
                ) != 0
            ) {
                ciphart_err("incorrect password or corrupted input");
                ciphart_free(
                    buf_cleartext,
                    buf_ciphertext,
                    buf_entropy,
                    header, key,
                    fp_in, fp_out
                );
                return 1;
            }
            if (
                tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && ! eof
            ) {
                ciphart_err("premature end of input");
                ciphart_free(
                    buf_cleartext,
                    buf_ciphertext,
                    buf_entropy,
                    header, key,
                    fp_in, fp_out
                );
                return 1;
            }
            fwrite(buf_cleartext, 1, (size_t) out_len, fp_out);
        } while (! eof);
    }

    ciphart_free(
        buf_cleartext,
        buf_ciphertext,
        buf_entropy,
        header, key,
        fp_in, fp_out
    );
    return 0;
}

/* print error */
void ciphart_err(const char *fmt, ...) {
    fprintf(stderr,"%s!!!%s ", COLOR_ERR, COLOR_RESET);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr,"\n");
}

/* print info */
void ciphart_info(const char *fmt, ...) {
    fprintf(stderr,"%s>>>%s ", COLOR_INFO, COLOR_RESET);
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
    fprintf(stderr,"\n");
}

/* print banner */
void ciphart_banner(char *exec_name) {
    fprintf(
        stderr,
        "%s%s v%s  copyright (C) %s  caveman\n"
        "%s\n\n"
        "this program comes with ABSOLUTELY NO WARRANTY; for details\n"
        "type `%s w'.  this is free software, and you are welcome to\n"
        "redistribute it under certain conditions; type `%s c' for\n"
        "details.%s\n\n",
        COLOR_BANNER, APP_NAME, APP_VERSION, APP_YEAR, APP_URL, exec_name,
        exec_name, COLOR_RESET
    );
}

/* print help */
void ciphart_help(char *exec_name) {
    fprintf(
        stdout,
        "%s {e,d} PIN POUT [H]\n"
        "%s {w,c,h}\n\n"
        "   e     enctypts plaintext in PIN into ciphertext in POUT.\n\n"
        "   d     decrypts ciphertext in PIN into plaintext in POUT.\n\n"
        "   PIN   path to input file.  STDIN if '-'.\n\n"
        "   POUT  path to output file.  STDOUT if '-'.\n\n"
        "   H     increase in password brute-forcing difficulty in\n"
        "         the unit of entropy bits.  practically, it has the\n"
        "         same effect of increasing the entropy of your password\n"
        "         by H many bits, without actually using a more complex\n"
        "         password.  so you can think of this as: how many bits\n"
        "         of entropy would you like %s to inject into your\n"
        "         password, in addition to the entropy bits already in\n"
        "         your password?  minimum is 0, maximum is %ld, default\n"
        "         is 30.\n\n"
        "         this is a very cool feature to allow you, the user, to\n"
        "         tune KDF's complexity in terms of entropy bits.  no\n"
        "         other app has this feature as far as i know; only\n"
        "         %s has this mega-neat feature.\n\n"
        "         other apps just spit some raw KDF parameters at you,\n"
        "         and simply expect you to suck it, without really\n"
        "         knowing how much of entropy-equivalency bits are you\n"
        "         gaining.  how can you know if you've sucked enough?\n"
        "         did you suck enough?  or should you suck even more?\n"
        "         you simply don't know!  but %s elegantly quantifies\n"
        "         your suckage in security terms in the unit of entropy\n"
        "         bits, so that, at least, you have an idea about how\n"
        "         good your sucking is.\n\n"
        "   w     shows warranty notice.\n\n"
        "   c     shows usage conditions.\n\n"
        "   h     shows this help.\n",
        exec_name, exec_name, APP_NAME,
        BITS_ENTROPY, APP_NAME, APP_NAME
    );
}

/* fputs */
int ciphart_fputs(const char *s) {
    if (fputs(s, stdout) == EOF) {
        ciphart_err("failed fputsing to stderr");
        return 1;
    }
    return 0;
}

/* free heaps */
void ciphart_free(
    unsigned char *h1, unsigned char *h2, unsigned char *h3,
    unsigned char *h4, unsigned char *h5, FILE *fp1, FILE *fp2 
) {
    if (h1 != NULL) sodium_free(h1);
    if (h2 != NULL) sodium_free(h2);
    if (h3 != NULL) sodium_free(h3);
    if (h4 != NULL) sodium_free(h4);
    if (h5 != NULL) sodium_free(h5);
    if (fp1 != NULL) fclose(fp1);
    if (fp2 != NULL) fclose(fp2);
}

/* obtain key from password from STDIN */
void ciphart_get_key(unsigned char *key) {
    unsigned char *buf;
    buf = sodium_malloc(CHUNK_PASS);
    crypto_generichash_state state;
    size_t rlen;
    crypto_generichash_init(&state, NULL, 0, SIZE_KEY);
    ciphart_info("reading password from STDIN (end by EOF)...");
    do {
        rlen = fread(buf, 1, CHUNK_PASS, stdin);
        crypto_generichash_update(&state, buf, rlen);
    } while (! feof(stdin));
    crypto_generichash_final(&state, key, SIZE_KEY);
    rewind(stdin);
    sodium_free(buf);
}

/* exponentiation function */
unsigned long long cipher_pow(long entropy) {
    long i;
    unsigned long long exp = 2;
    for (i = 0; i < entropy; i++) exp *= 2;
    return exp;
}
