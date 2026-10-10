#include <time.h>
#include "hid.h"

#include <string.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/l2cap.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

/* Note : on utilise str2ba/ba2str de libbluetooth plutôt qu'un parser maison.
   Le type d'adresse est BDADDR_BREDR (Bluetooth Classic), pas LE. */

static void msleep(long ms)
{
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

static int l2_connect(const bdaddr_t *src, const bdaddr_t *dst, uint16_t psm)
{
    int fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
    if (fd < 0) return -1;

    struct sockaddr_l2 a;
    memset(&a, 0, sizeof(a));
    a.l2_family = AF_BLUETOOTH;
    a.l2_bdaddr = *src;
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0)
        goto fail;

    memset(&a, 0, sizeof(a));
    a.l2_family = AF_BLUETOOTH;
    a.l2_psm = htobs(psm);
    a.l2_bdaddr = *dst;
    a.l2_bdaddr_type = BDADDR_BREDR;

    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0)
        goto fail;

    return fd;
fail:
    close(fd);
    return -1;
}

int hid_open(hid_t *h, int hci_dev, const char *target_mac)
{
    memset(h, 0, sizeof(*h));
    h->ctrl_fd = h->intr_fd = -1;

    bdaddr_t src, dst;
    str2ba(target_mac, &dst);

    int hs = hci_open_dev(hci_dev);
    if (hs < 0) {
        fprintf(stderr, "hid: hci%d indisponible: %s\n", hci_dev, strerror(errno));
        return -1;
    }
    int r = hci_read_bd_addr(hs, &src, 1000);
    close(hs);
    if (r < 0) return -1;

    /* TODO : remplacer par votre module l2cap.c si son API supporte
       la connexion sortante sur PSM — c'est le point de couture idéal. */
    h->ctrl_fd = l2_connect(&src, &dst, 0x11);
    if (h->ctrl_fd < 0) {
        fprintf(stderr, "hid: échec PSM 0x11: %s\n", strerror(errno));
        return -1;
    }
    h->intr_fd = l2_connect(&src, &dst, 0x13);
    if (h->intr_fd < 0) {
        fprintf(stderr, "hid: échec PSM 0x13: %s\n", strerror(errno));
        hid_close(h);
        return -1;
    }
    h->connected = true;
    return 0;
}

void hid_close(hid_t *h)
{
    if (!h) return;
    if (h->ctrl_fd >= 0) close(h->ctrl_fd);
    if (h->intr_fd >= 0) close(h->intr_fd);
    h->ctrl_fd = h->intr_fd = -1;
    h->connected = false;
}

int hid_send_report(hid_t *h, uint8_t mods, const uint8_t keys[6])
{
    if (!h->connected) return -1;

    uint8_t pkt[8] = { 0xA1, mods, 0x00,
                       keys[0], keys[1], keys[2], keys[3], keys[4] };
    /* keys[5] serait l'octet 8 — le rapport boot clavier fait 8 octets au total
       avec l'entête 0xA1 : header(1) + mods(1) + reserved(1) + 6 touches.
       On écrit donc 9 octets : */
    uint8_t out[9] = { 0xA1, mods, 0x00,
                       keys[0], keys[1], keys[2], keys[3], keys[4], keys[5] };

    (void)pkt;
    return write(h->intr_fd, out, sizeof(out)) == sizeof(out) ? 0 : -1;
}

int hid_keypress(hid_t *h, uint8_t mods, uint8_t key)
{
    uint8_t keys[6] = { key, 0, 0, 0, 0, 0 };
    if (hid_send_report(h, mods, keys) < 0) return -1;
    msleep(10);
    memset(keys, 0, sizeof(keys));
    return hid_send_report(h, 0, keys);
}

int hid_sink(void *ctx, ducky_ev_t ev, uint32_t a, uint32_t b)
{
    hid_t *h = ctx;
    if (ev == DUCKY_DELAY)
        { msleep((long)a); return 0; }
    return hid_keypress(h, (uint8_t)a, (uint8_t)b);
}
