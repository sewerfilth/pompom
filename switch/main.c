/*
 * pompom Switch homebrew demo
 *
 * Demonstrates the cipher, padlock, and profiling on Nintendo Switch.
 * No networking (NO_POSIX_SOCKETS) — uses the crypto core only.
 */
#include <switch.h>
#include <stdio.h>
#include <string.h>

#include "pompom/padlock.h"
#include "pompom/cipher.h"
#include "pompom/accel.h"
#include "pompom/profile.h"

static void demo_cipher(void) {
    uint8_t key[8]   = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
    uint8_t nonce[4] = {0xDE,0xAD,0xBE,0xEF};

    const char *msg = "Hello from Nintendo Switch!";
    size_t len = strlen(msg);

    uint8_t ct[64], pt[64];
    pompom_state_t enc, dec;

    pompom_init(&enc, key, nonce);
    pompom_crypt(&enc, (const uint8_t *)msg, ct, len);

    pompom_init(&dec, key, nonce);
    pompom_crypt(&dec, ct, pt, len);
    pt[len] = '\0';

    printf("  original:  %s\n", msg);
    printf("  encrypted: ");
    for (size_t i = 0; i < len && i < 16; i++) printf("%02x", ct[i]);
    printf("...\n");
    printf("  decrypted: %s\n", (char *)pt);
    printf("  roundtrip: %s\n\n", memcmp(pt, msg, len) == 0 ? "OK" : "FAIL");
}

static void demo_padlock(void) {
    pompom_lock_t lock;
    pompom_lock_init(&lock, 0x42);
    pompom_dial(&lock, "switch", 6);
    pompom_lock_set(&lock);

    /* Correct combo */
    pompom_dial(&lock, "switch", 6);
    int correct = pompom_lock_try(&lock) == 0;

    /* Wrong combo */
    pompom_lock_init(&lock, 0x42);
    pompom_dial(&lock, "switch", 6);
    pompom_lock_set(&lock);
    pompom_dial(&lock, "wrong!", 6);
    int wrong = pompom_lock_try(&lock) != 0;

    printf("  correct combo: %s\n", correct ? "UNLOCKED" : "FAIL");
    printf("  wrong combo:   %s\n\n", wrong ? "LOCKED" : "FAIL");
}

static void demo_accel(void) {
    int accel = pompom_accel_detect();
    printf("  acceleration: %s\n\n", pompom_accel_name(accel));
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    consoleInit(NULL);

    printf("=== pompom cipher demo ===\n\n");

    printf("[accel detection]\n");
    demo_accel();

    printf("[cipher roundtrip]\n");
    demo_cipher();

    printf("[padlock lock/unlock]\n");
    demo_padlock();

    printf("Press + to exit.\n");

    padConfigureInput(1, HidNpadStyleSet_NpadStandard);
    PadState pad;
    padInitializeDefault(&pad);

    while (appletMainLoop()) {
        padUpdate(&pad);
        if (padGetButtonsDown(&pad) & HidNpadButton_Plus)
            break;
        consoleUpdate(NULL);
    }

    consoleExit(NULL);
    return 0;
}
