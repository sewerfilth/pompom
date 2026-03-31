#ifndef POMPOM_WAL_H
#define POMPOM_WAL_H

#include <stdint.h>
#include <stddef.h>
#include "pompom/cipher.h"

#define POMPOM_WAL_MAGIC 0x4C575050  /* "PPWL" little-endian */

typedef struct pompom_wal pompom_wal_t;

/* Open or create a WAL file. Returns NULL on failure. */
pompom_wal_t *pompom_wal_open(const char *path);

/* Close WAL (fsync + free). */
void pompom_wal_close(pompom_wal_t *wal);

/* Append current cipher state to WAL (fsync'd). Returns 0 on success. */
int pompom_wal_checkpoint(pompom_wal_t *wal, const pompom_state_t *st);

/* Recover most recent valid state. Returns 0 on success, -1 if empty/corrupt. */
int pompom_wal_recover(pompom_wal_t *wal, pompom_state_t *st);

/* Truncate WAL back to header only. Call after successful recovery. */
int pompom_wal_truncate(pompom_wal_t *wal);

/* Number of entries currently in WAL. */
size_t pompom_wal_count(const pompom_wal_t *wal);

#endif
