# Payloads (DuckyScript)

Syntaxe supportée par src/ducky.c :

    REM / #          commentaire
    DELAY n          pause n ms
    STRING texte     tape le texte (ASCII US uniquement, pas d'accents)
    GUI r            combo modificateur(s) + touche
    CTRL-ALT t       plusieurs modificateurs
    ENTER/ESC/TAB/F1..F12/...  touche seule
    REPEAT n         rejoue la ligne précédente n fois

Usage:
    bleurp hid AA:BB:CC:DD:EE:FF -f payloads/demo-hello.txt

⚠️ Uniquement sur des appareils autorisés.
