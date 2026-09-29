#ifndef HID_H
#define HID_H

#include <stdint.h>
#include <stdbool.h>
#include "ducky.h"

typedef struct {
    int ctrl_fd;   /* L2CAP PSM 0x11 (contrôle) */
    int intr_fd;   /* L2CAP PSM 0x13 (interruption) */
    bool connected;
} hid_t;

/* hci_dev : index de l'adaptateur (cf. votre hci_dev.c) */
int  hid_open(hid_t *h, int hci_dev, const char *target_mac);
void hid_close(hid_t *h);
int  hid_send_report(hid_t *h, uint8_t mods, const uint8_t keys[6]);
int  hid_keypress(hid_t *h, uint8_t mods, uint8_t key);

/* Adaptateur ducky_sink_fn → transport HID (usage : ducky_run(f, hid_sink, &hid)) */
int  hid_sink(void *ctx, ducky_ev_t ev, uint32_t a, uint32_t b);

#endif
