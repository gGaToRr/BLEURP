#include <string.h>
#include <strings.h>
#include "ducky.h"
#include "keymap.h"

#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#define DUCKY_LINE_MAX 512

static int emit_key(ducky_sink_fn sink, void *ctx, uint8_t mods, uint8_t key)
{
    return sink(ctx, DUCKY_KEY, mods, key);
}

/* Une ligne hors STRING : tokens séparés par espaces et '-'.
   Les premiers tokens doivent être des modificateurs, le dernier une touche. */
static int exec_combo(const char *line, ducky_sink_fn sink, void *ctx)
{
    char buf[DUCKY_LINE_MAX];
    snprintf(buf, sizeof(buf), "%s", line);

    uint8_t mods = 0;
    uint8_t key = 0;
    bool have_key = false;
    char *save = NULL;

    for (char *tok = strtok_r(buf, " \t-", &save); tok;
         tok = strtok_r(NULL, " \t-", &save)) {

        if (keymap_named(tok, &mods, &key)) {
            if (!have_key && key != 0)
                have_key = true;
        } else {
            fprintf(stderr, "ducky: touche inconnue '%s'\n", tok);
            return 0;
        }
    }

    /* "GUI" seul, ou "GUI r" */
    return emit_key(sink, ctx, mods, have_key ? key : 0);
}

static int exec_line(const char *line, char *repeat_buf,
                     ducky_sink_fn sink, void *ctx, int *count)
{
    /* Lignes ignorées */
    if (line[0] == '\0' || line[0] == '#')
        return 0;
    if (!strncasecmp(line, "REM", 3) && (line[3] == '\0' || line[3] == ' '))
        return 0;

    /* REPEAT n : rejoue la ligne précédente */
    if (!strncasecmp(line, "REPEAT", 6) && (line[6] == '\0' || line[6] == ' ')) {
        int n = atoi(line + 6);
        if (n <= 0 || repeat_buf[0] == '\0')
            return 0;
        for (int i = 0; i < n; i++) {
            int r = exec_line(repeat_buf, repeat_buf, sink, ctx, count);
            if (r < 0) return r;
        }
        return 0;
    }

    /* STRING : le reste de la ligne est typé littéralement */
    if (!strncasecmp(line, "STRING", 6) && (line[6] == '\0' || line[6] == ' ')) {
        const char *text = line + 6 + (line[6] == ' ' ? 1 : 0);
        for (; *text; text++) {
            uint8_t mods = 0, key = 0;
            if (!keymap_ascii(*text, &mods, &key)) {
                fprintf(stderr, "ducky: caractère non mappable '%c' ignoré\n", *text);
                continue;
            }
            (*count)++;
            if (emit_key(sink, ctx, mods, key) < 0)
                return -1;
        }
        return 0;
    }

    /* DELAY n */
    if (!strncasecmp(line, "DELAY", 5) && (line[5] == '\0' || line[5] == ' ')) {
        uint32_t ms = (uint32_t)strtoul(line + 5, NULL, 10);
        (*count)++;
        if (sink(ctx, DUCKY_DELAY, ms, 0) < 0)
            return -1;
        return 0;
    }

    /* Combo / touche seule */
    (*count)++;
    if (exec_combo(line, sink, ctx) < 0)
        return -1;

    snprintf(repeat_buf, DUCKY_LINE_MAX, "%s", line);
    return 0;
}

int ducky_run(FILE *in, ducky_sink_fn sink, void *ctx)
{
    char line[DUCKY_LINE_MAX];
    char repeat_buf[DUCKY_LINE_MAX] = "";
    int count = 0;

    while (fgets(line, sizeof(line), in)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (exec_line(line, repeat_buf, sink, ctx, &count) < 0)
            return -1;
    }
    return count;
}

int ducky_run_str(const char *script, ducky_sink_fn sink, void *ctx)
{
    FILE *f = fmemopen((void *)script, strlen(script), "r");
    if (!f) return -1;
    int r = ducky_run(f, sink, ctx);
    fclose(f);
    return r;
}
