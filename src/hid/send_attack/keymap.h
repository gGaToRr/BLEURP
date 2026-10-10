#ifndef KEYMAP_H
#define KEYMAP_H

#include <stdint.h>
#include <stdbool.h>

/* Modificateurs HID */
#define HID_MOD_LCTRL  0x01
#define HID_MOD_LSHIFT 0x02
#define HID_MOD_LALT   0x04
#define HID_MOD_LGUI   0x08
#define HID_MOD_RCTRL  0x10
#define HID_MOD_RSHIFT 0x20
#define HID_MOD_RALT   0x40
#define HID_MOD_RGUI   0x80

/* keymap_ascii : convertit un caractère. OR dans *mods (Shift pour A-Z, etc.).
   Retourne false si le caractère n'est pas mappable. */
bool keymap_ascii(char c, uint8_t *mods, uint8_t *key);

/* keymap_named : "GUI", "CTRL", "ALT", "SHIFT" (OR mods, key=0),
   "ENTER", "F1".."F12", etc., ou un caractère seul ("a", "?").
   OR dans *mods. */
bool keymap_named(const char *name, uint8_t *mods, uint8_t *key);

#endif
