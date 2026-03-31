ARCH ?= $(shell uname -m)

# Normalize host arch names
ifeq ($(ARCH),aarch64)
  ARCH := arm
endif
ifeq ($(ARCH),arm64)
  ARCH := arm
endif
ifeq ($(ARCH),i686)
  ARCH := x86_32
endif
ifeq ($(ARCH),i386)
  ARCH := x86_32
endif

# Toolchain defaults
CC      ?= cc
AR      ?= ar
CFLAGS  := -Wall -Wextra -Werror -Iinclude
ARFLAGS := rcs

# Architecture-specific assembler setup
ifeq ($(ARCH),arm)
  AS      := $(CC)
  ASFLAGS := -c
  ASM_EXT := s
else ifeq ($(ARCH),x86_64)
  AS      := nasm
  ASFLAGS := -f elf64
  ASM_EXT := asm
else ifeq ($(ARCH),x86_32)
  AS      := nasm
  ASFLAGS := -f elf32
  ASM_EXT := asm
  CFLAGS  += -m32
else
  $(error Unsupported ARCH=$(ARCH). Use arm, x86_64, or x86_32)
endif

# macOS object format override for nasm
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  ifeq ($(ARCH),x86_64)
    ASFLAGS := -f macho64
  else ifeq ($(ARCH),x86_32)
    ASFLAGS := -f macho32
  endif
endif

# Sources
ASM_SRC := $(wildcard asm/$(ARCH)/*.$(ASM_EXT))
C_SRC   := $(wildcard src/*.c)

# Objects
BUILDDIR := build/$(ARCH)
ASM_OBJ  := $(patsubst asm/$(ARCH)/%.$(ASM_EXT),$(BUILDDIR)/%.o,$(ASM_SRC))
C_OBJ    := $(patsubst src/%.c,$(BUILDDIR)/%.o,$(C_SRC))
OBJS     := $(ASM_OBJ) $(C_OBJ)

TARGET := $(BUILDDIR)/libpompom.a

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS) | $(BUILDDIR)
	$(AR) $(ARFLAGS) $@ $^

$(BUILDDIR)/%.o: asm/$(ARCH)/%.$(ASM_EXT) | $(BUILDDIR)
	$(AS) $(ASFLAGS) -o $@ $<

$(BUILDDIR)/%.o: src/%.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILDDIR):
	mkdir -p $@

clean:
	rm -rf build/
