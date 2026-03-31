#include "pompom/wal.h"

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define WAL_HDR_SZ   8
#define WAL_ENTRY_SZ 16

typedef struct {
    uint32_t magic;
    uint8_t  version;
    uint8_t  reserved[3];
} wal_hdr_t;

/*
 * WAL entry: 16 bytes, naturally aligned.
 *   t(4) + front(1) + lane(8) + seed(1) + crc(1) + pad(1) = 16
 */
typedef struct {
    uint32_t t;
    uint8_t  front;
    uint8_t  lane[8];
    uint8_t  seed;
    uint8_t  crc;
    uint8_t  pad;
} wal_entry_t;

struct pompom_wal {
    int    fd;
    size_t count;
};

/* CRC-8/CCITT (poly 0x07) */
static uint8_t wal_crc8(const uint8_t *data, size_t len) {
    uint8_t crc = 0;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++)
            crc = (crc & 0x80)
                ? (uint8_t)((crc << 1) ^ 0x07)
                : (uint8_t)(crc << 1);
    }
    return crc;
}

pompom_wal_t *pompom_wal_open(const char *path) {
    int fd = open(path, O_RDWR | O_CREAT, 0600);
    if (fd < 0) return NULL;

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return NULL; }

    size_t count = 0;

    if (st.st_size == 0) {
        wal_hdr_t hdr;
        memset(&hdr, 0, sizeof(hdr));
        hdr.magic   = POMPOM_WAL_MAGIC;
        hdr.version = 1;
        if (write(fd, &hdr, WAL_HDR_SZ) != WAL_HDR_SZ) {
            close(fd); return NULL;
        }
        fsync(fd);
    } else if ((size_t)st.st_size < WAL_HDR_SZ) {
        close(fd); return NULL;
    } else {
        wal_hdr_t hdr;
        if (pread(fd, &hdr, WAL_HDR_SZ, 0) != WAL_HDR_SZ) {
            close(fd); return NULL;
        }
        if (hdr.magic != POMPOM_WAL_MAGIC || hdr.version != 1) {
            close(fd); return NULL;
        }
        count = ((size_t)st.st_size - WAL_HDR_SZ) / WAL_ENTRY_SZ;
    }

    pompom_wal_t *wal = malloc(sizeof(*wal));
    if (!wal) { close(fd); return NULL; }
    wal->fd    = fd;
    wal->count = count;
    return wal;
}

void pompom_wal_close(pompom_wal_t *wal) {
    if (!wal) return;
    fsync(wal->fd);
    close(wal->fd);
    free(wal);
}

int pompom_wal_checkpoint(pompom_wal_t *wal, const pompom_state_t *st) {
    wal_entry_t e;
    e.t     = st->t;
    e.front = st->front;
    memcpy(e.lane, st->lane, 8);
    e.seed  = st->seed;
    e.pad   = 0;
    e.crc   = wal_crc8((const uint8_t *)&e,
                        (size_t)((const uint8_t *)&e.crc - (const uint8_t *)&e));

    off_t pos = WAL_HDR_SZ + (off_t)wal->count * WAL_ENTRY_SZ;
    if (pwrite(wal->fd, &e, WAL_ENTRY_SZ, pos) != WAL_ENTRY_SZ)
        return -1;
    fsync(wal->fd);
    wal->count++;
    return 0;
}

int pompom_wal_recover(pompom_wal_t *wal, pompom_state_t *st) {
    for (size_t i = wal->count; i > 0; i--) {
        wal_entry_t e;
        off_t pos = WAL_HDR_SZ + (off_t)(i - 1) * WAL_ENTRY_SZ;
        if (pread(wal->fd, &e, WAL_ENTRY_SZ, pos) != WAL_ENTRY_SZ)
            continue;

        uint8_t expected = wal_crc8((const uint8_t *)&e,
                                    (size_t)((const uint8_t *)&e.crc - (const uint8_t *)&e));
        if (e.crc != expected)
            continue;

        st->t     = e.t;
        st->front = e.front;
        memcpy(st->lane, e.lane, 8);
        st->seed  = e.seed;
        return 0;
    }
    return -1;
}

int pompom_wal_truncate(pompom_wal_t *wal) {
    if (ftruncate(wal->fd, WAL_HDR_SZ) < 0) return -1;
    wal->count = 0;
    return 0;
}

size_t pompom_wal_count(const pompom_wal_t *wal) {
    return wal->count;
}
