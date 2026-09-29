# ========================================
#  nom du fichier: Makefile
#  description courte: Build and test driver for BLEURP. Compiles the C
#  sources into object files and builds/runs one test binary per test file.
#  Targets: all (compile), test (build + run tests), clean.
#  dernière modification : 2026-09-26
#  auteur: GitHub/@gGaToRr
# ========================================

CC      := gcc
CFLAGS  := -std=c11 -Wall -Wextra -Werror -O2 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -Isrc -Isrc/send_attack -Isrc/smp_native -Itests
LDLIBS  := -lbluetooth -lm $(shell pkg-config --libs dbus-1)
CFLAGS  += $(shell pkg-config --cflags dbus-1)
# Absolute path to the bundled FIGlet font used for the menu banner (see
# src/banner.c), baked in at build time so the binary finds it regardless
# of the working directory it is run from.
CFLAGS  += -DBLEURP_FONT_PATH='"$(abspath assets/fonts/slant.flf)"'
# Same idea for the bundled DuckyScript payloads, listed by the menu's HID
# wizard (see cmd_menu in src/main.c).
CFLAGS  += -DBLEURP_PAYLOADS_DIR='"$(abspath src/send_attack/payloads)"'
BUILD   := build
BIN     := $(BUILD)/bleurp

# Library sources (excludes main.c so tests can link freely).
SRC := $(filter-out src/main.c,$(wildcard src/*.c) $(wildcard src/send_attack/*.c) $(wildcard src/smp_native/*.c))
OBJ := $(SRC:src/%.c=$(BUILD)/%.o)

# One test binary per tests/test_*.c file.
TEST_SRC := $(wildcard tests/test_*.c)
TEST_BIN := $(TEST_SRC:tests/%.c=$(BUILD)/%)

.PHONY: all test clean setcap run

# Default: build the bleurp binary.
all: $(BIN)

# Link the scanner from the library objects plus main.
$(BIN): $(OBJ) $(BUILD)/main.o | $(BUILD)
	$(CC) $(CFLAGS) $(OBJ) $(BUILD)/main.o -o $@ $(LDLIBS)

# Compile a library object.
$(BUILD)/%.o: src/%.c | $(BUILD)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

# Link a test binary against every library object.
$(BUILD)/test_%: tests/test_%.c $(OBJ) | $(BUILD)
	$(CC) $(CFLAGS) $< $(OBJ) -o $@ $(LDLIBS)

# Build and run the whole test suite; non-zero exit if any binary fails.
test: $(TEST_BIN)
	@echo "== running tests =="
	@fail=0; for t in $(TEST_BIN); do echo; ./$$t || fail=1; done; \
	 echo; if [ $$fail -eq 0 ]; then echo "ALL TESTS PASSED"; \
	 else echo "TESTS FAILED"; exit 1; fi

$(BUILD):
	@mkdir -p $(BUILD)

# Grant the capabilities needed for kernel mgmt discovery (needs sudo once).
setcap: $(BIN)
	sudo setcap cap_net_raw,cap_net_admin+eip $(BIN)

# Run the scanner (needs the capabilities above, or run under sudo).
run: $(BIN)
	$(BIN)

clean:
	rm -rf $(BUILD)
