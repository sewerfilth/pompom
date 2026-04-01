#──────────────────────────────────────────────────────────────────
# pompom Switch homebrew (NRO)
#
# Usage:
#   make                   → builds pompom-demo.nro
#   make run SWITCH_IP=x   → sends to Switch via nxlink
#   make clean
#
# Prerequisites:
#   Build libpompom for Switch first:
#     cd .. && ./build.sh --target libnx
#──────────────────────────────────────────────────────────────────

APP_NAME    := pompom-demo
APP_TITLE   := pompom cipher demo
APP_AUTHOR  := pompom
APP_VERSION := 1.0.0
APP_SOURCES := main.c
APP_LIBS    := ../build/libnx/libpompom.a

CFLAGS += -I../include

include ../../shared/switch-template/Makefile
