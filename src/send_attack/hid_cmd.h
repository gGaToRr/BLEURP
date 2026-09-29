#ifndef HID_CMD_H
#define HID_CMD_H

/* Sous-commande "hid" du CLI.
   Usage : <prog> hid -i hci0 -t AA:BB:CC:DD:EE:FF -f payload.txt */
int hid_cmd_run(int argc, char **argv);

#endif
