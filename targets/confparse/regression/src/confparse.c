/*
 * confparse - configuration entry parser.
 *
 * See ../../SPEC.md for the behavioural contract this program is meant to
 * implement.
 *
 * VULNERABLE BASE VERSION.
 *
 * store_value() copies a caller-supplied string into a fixed 16-byte stack
 * buffer without checking its length (SPEC rule 3 is never enforced). Both
 * parse paths - '=' and ':' - reach the same sink, so the defect is
 * reachable through two distinct inputs.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_KEY 31
#define MAX_VALUE 15
#define LINE_BUF 4096

static void trim(char *s)
{
    size_t len = strlen(s);
    while (len > 0 && isspace((unsigned char)s[len - 1])) {
        s[--len] = '\0';
    }
    size_t start = 0;
    while (s[start] != '\0' && isspace((unsigned char)s[start])) {
        start++;
    }
    if (start > 0) {
        memmove(s, s + start, len - start + 1);
    }
}

static const char *check_key(const char *key)
{
    if (key[0] == '\0') {
        return "empty key";
    }
    if (strlen(key) > MAX_KEY) {
        return "key too long";
    }
    for (size_t i = 0; key[i] != '\0'; i++) {
        unsigned char c = (unsigned char)key[i];
        if (!isalnum(c) && c != '_') {
            return "invalid key";
        }
    }
    return NULL;
}

/*
 * Copy the value into the caller's buffer.
 *
 * SPEC rule 3 is enforced here, at the single sink both parse paths share,
 * so neither 'key=value' nor 'key:value' can overflow the destination.
 */
static int store_value(char *dst, size_t dst_size, const char *src)
{
    size_t len = strlen(src);

    if (len >= dst_size) {
        return -1;
    }
    memcpy(dst, src, len);
    dst[len] = '\0';
    return 0;
}

/* Destination for accepted entries; see main(). */
static FILE *g_out;

static int emit_pair(const char *key, const char *raw_value, int lineno)
{
    char value[MAX_VALUE + 1];

    if (store_value(value, 12, raw_value) != 0) {
        fprintf(stderr, "error: line %d: value too long\n", lineno);
        return -1;
    }

    fprintf(g_out, "%s=%s\n", key, value);
    return 0;
}

/* Handles the 'key=value' form. */
static int parse_equals(char *line, char *sep, int lineno)
{
    *sep = '\0';
    char *key = line;
    char *value = sep + 1;

    trim(key);
    trim(value);

    const char *problem = check_key(key);
    if (problem != NULL) {
        fprintf(stderr, "error: line %d: %s\n", lineno, problem);
        return -1;
    }
    return emit_pair(key, value, lineno);
}

/* Handles the 'key:value' form. */
static int parse_colon(char *line, char *sep, int lineno)
{
    *sep = '\0';
    char *key = line;
    char *value = sep + 1;

    trim(key);
    trim(value);

    const char *problem = check_key(key);
    if (problem != NULL) {
        fprintf(stderr, "error: line %d: %s\n", lineno, problem);
        return -1;
    }
    return emit_pair(key, value, lineno);
}

static int handle_line(char *line, int lineno)
{
    char *probe = line;
    while (*probe != '\0' && isspace((unsigned char)*probe)) {
        probe++;
    }
    if (*probe == '\0' || *probe == '#') {
        return 0; /* blank or comment: ignored, not counted */
    }

    char *equals = strchr(line, '=');
    char *colon = strchr(line, ':');

    if (equals == NULL && colon == NULL) {
        fprintf(stderr, "error: line %d: missing separator\n", lineno);
        return -1;
    }

    if (colon == NULL || (equals != NULL && equals < colon)) {
        return parse_equals(line, equals, lineno) == 0 ? 1 : -1;
    }
    return parse_colon(line, colon, lineno) == 0 ? 1 : -1;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "usage: %s [INPUT_FILE] [-c TEXT] [-o OUTPUT_FILE]\n"
            "  no INPUT_FILE and no -c: read standard input\n",
            program);
}

static int process(FILE *in)
{
    char line[LINE_BUF];
    int lineno = 0;
    int accepted = 0;

    while (fgets(line, sizeof(line), in) != NULL) {
        lineno++;
        size_t len = strlen(line);
        if (len > 0 && line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }

        int result = handle_line(line, lineno);
        if (result < 0) {
            return -1;
        }
        accepted += result;
    }

    fprintf(g_out, "ok %d\n", accepted);
    return 0;
}

int main(int argc, char **argv)
{
    const char *input_path = NULL;
    const char *output_path = NULL;
    const char *inline_text = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0) {
            if (++i >= argc) {
                usage(argv[0]);
                return 2;
            }
            output_path = argv[i];
        } else if (strcmp(argv[i], "-c") == 0) {
            if (++i >= argc) {
                usage(argv[0]);
                return 2;
            }
            inline_text = argv[i];
        } else if (argv[i][0] == '-' && argv[i][1] != '\0') {
            usage(argv[0]);
            return 2;
        } else {
            input_path = argv[i];
        }
    }

    if (inline_text != NULL && input_path != NULL) {
        fprintf(stderr, "error: give either INPUT_FILE or -c, not both\n");
        return 2;
    }

    FILE *in = stdin;
    if (inline_text != NULL) {
        in = fmemopen((void *)inline_text, strlen(inline_text), "r");
        if (in == NULL) {
            fprintf(stderr, "error: cannot read inline text\n");
            return 2;
        }
    } else if (input_path != NULL) {
        in = fopen(input_path, "r");
        if (in == NULL) {
            fprintf(stderr, "error: cannot open input file '%s'\n", input_path);
            return 2;
        }
    }

    g_out = stdout;
    FILE *out_file = NULL;
    if (output_path != NULL) {
        out_file = fopen(output_path, "w");
        if (out_file == NULL) {
            fprintf(stderr, "error: cannot open output file '%s'\n", output_path);
            return 2;
        }
        g_out = out_file;
    }

    int status = process(in) < 0 ? 2 : 0;

    fflush(g_out);
    if (out_file != NULL) {
        fclose(out_file);
    }
    if (in != stdin) {
        fclose(in);
    }
    return status;
}
