#include "keymap.h"
#include <strings.h>
#include <string.h>

bool keymap_ascii(char c, uint8_t *mods, uint8_t *key)
{
    if (c >= 'a' && c <= 'z') { *key = 0x04 + (c - 'a'); return true; }
    if (c >= 'A' && c <= 'Z') { *key = 0x04 + (c - 'A'); *mods |= HID_MOD_LSHIFT; return true; }
    if (c >= '1' && c <= '9') { *key = 0x1E + (c - '1'); return true; }

    switch (c) {
    case '0': *key = 0x27; return true;
    case '\n': *key = 0x28; return true;
    case '\t': *key = 0x2B; return true;
    case ' ':  *key = 0x2C; return true;
    case '-': *key = 0x2D; return true;   case '_': *key = 0x2D; *mods |= HID_MOD_LSHIFT; return true;
    case '=': *key = 0x2E; return true;   case '+': *key = 0x2E; *mods |= HID_MOD_LSHIFT; return true;
    case '[': *key = 0x2F; return true;   case '{': *key = 0x2F; *mods |= HID_MOD_LSHIFT; return true;
    case ']': *key = 0x30; return true;   case '}': *key = 0x30; *mods |= HID_MOD_LSHIFT; return true;
    case '\\':*key = 0x31; return true;   case '|': *key = 0x31; *mods |= HID_MOD_LSHIFT; return true;
    case ';': *key = 0x33; return true;   case ':': *key = 0x33; *mods |= HID_MOD_LSHIFT; return true;
    case '\'':*key = 0x34; return true;   case '"': *key = 0x34; *mods |= HID_MOD_LSHIFT; return true;
    case '`': *key = 0x35; return true;   case '~': *key = 0x35; *mods |= HID_MOD_LSHIFT; return true;
    case ',': *key = 0x36; return true;   case '<': *key = 0x36; *mods |= HID_MOD_LSHIFT; return true;
    case '.': *key = 0x37; return true;   case '>': *key = 0x37; *mods |= HID_MOD_LSHIFT; return true;
    case '/': *key = 0x38; return true;   case '?': *key = 0x38; *mods |= HID_MOD_LSHIFT; return true;
    case '!': *key = 0x1E; *mods |= HID_MOD_LSHIFT; return true;
    case '@': *key = 0x1F; *mods |= HID_MOD_LSHIFT; return true;
    case '#': *key = 0x20; *mods |= HID_MOD_LSHIFT; return true;
    case '$': *key = 0x21; *mods |= HID_MOD_LSHIFT; return true;
    case '%': *key = 0x22; *mods |= HID_MOD_LSHIFT; return true;
    case '^': *key = 0x23; *mods |= HID_MOD_LSHIFT; return true;
    case '&': *key = 0x24; *mods |= HID_MOD_LSHIFT; return true;
    case '*': *key = 0x25; *mods |= HID_MOD_LSHIFT; return true;
    case '(': *key = 0x26; *mods |= HID_MOD_LSHIFT; return true;
    case ')': *key = 0x27; *mods |= HID_MOD_LSHIFT; return true;
    default:  return false;
    }
}

bool keymap_named(const char *name, uint8_t *mods, uint8_t *key)
{
    static const struct { const char *n; uint8_t k; } tbl[] = {
        {"ENTER",0x28},{"RETURN",0x28},{"ESC",0x29},{"ESCAPE",0x29},
        {"BACKSPACE",0x2A},{"BKSP",0x2A},{"TAB",0x2B},{"SPACE",0x2C},
        {"CAPSLOCK",0x39},{"DELETE",0x4C},{"DEL",0x4C},
        {"UP",0x52},{"DOWN",0x51},{"LEFT",0x50},{"RIGHT",0x4F},
        {"HOME",0x4A},{"END",0x4D},{"PAGEUP",0x4B},{"PAGEDOWN",0x4E},
        {"F1",0x3A},{"F2",0x3B},{"F3",0x3C},{"F4",0x3D},{"F5",0x3E},
        {"F6",0x3F},{"F7",0x40},{"F8",0x41},{"F9",0x42},{"F10",0x43},
        {"F11",0x44},{"F12",0x45},{NULL,0}
    };

    if (!strcasecmp(name, "GUI"))   { *mods |= HID_MOD_LGUI;   return true; }
    if (!strcasecmp(name, "CTRL"))  { *mods |= HID_MOD_LCTRL;  return true; }
    if (!strcasecmp(name, "ALT"))   { *mods |= HID_MOD_LALT;   return true; }
    if (!strcasecmp(name, "SHIFT")) { *mods |= HID_MOD_LSHIFT; return true; }

    for (int i = 0; tbl[i].n; i++)
        if (!strcasecmp(name, tbl[i].n)) { *key = tbl[i].k; return true; }

    if (strlen(name) == 1)
        return keymap_ascii(name[0], mods, key);

    return false;
}
