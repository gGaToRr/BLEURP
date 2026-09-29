#ifndef DUCKY_H
#define DUCKY_H

#include <stdint.h>
#include <stdio.h>

typedef enum {
    DUCKY_KEY   = 0,  /* a = modifiers, b = keycode            */
    DUCKY_DELAY = 1   /* a = millisecondes                      */
} ducky_ev_t;

/* Le parseur ne connaît pas Bluetooth : il émet vers un sink.
   Le sink peut capturer (tests) ou transmettre en HID (production). */
typedef int (*ducky_sink_fn)(void *ctx, ducky_ev_t ev, uint32_t a, uint32_t b);

/* Exécute un script DuckyScript depuis un flux.
   Retourne le nombre d'événements émis, -1 si le sink échoue. */
int ducky_run(FILE *in, ducky_sink_fn sink, void *ctx);

/* Variante pratique pour les tests. */
int ducky_run_str(const char *script, ducky_sink_fn sink, void *ctx);

#endif
