#include "ankah/session.h"
#include "ankah/files.h"

#include <mbedtls/sha256.h>
#include <inttypes.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_SESSIONS ANKAH_SESSION_CAPACITY
#define MAX_ANONYMOUS_UNSOLVED 3072
#define MAX_ANONYMOUS_UNSOLVED_PER_IP 64
#define MAX_PENDING_BYTES (64U * 1024U * 1024U)

static ankah_session sessions[MAX_SESSIONS];
static size_t pending_bytes;
static uint64_t mutation, queued_mutation, snapshot_generation;

struct ankah_post_payload {
    ankah_request *request;
    unsigned char *body;
    unsigned int pins;
};

void ankah_post_payload_release(ankah_post_payload *payload) {
    if (payload && --payload->pins == 0) {
        free(payload->request);
        free(payload->body);
        free(payload);
    }
}

static void random_hex(char output[33]) {
    static const char hex[] = "0123456789abcdef";
    unsigned char bytes[16];
    size_t i;
    if (ankah_random(bytes, sizeof(bytes)) != 0) { output[0] = 0; return; }
    for (i = 0; i < sizeof(bytes); ++i) {
        output[i * 2] = hex[bytes[i] >> 4];
        output[i * 2 + 1] = hex[bytes[i] & 15];
    }
    output[32] = 0;
}

static void release_post(ankah_session *session) {
    if (!session->saved_request) return;
    pending_bytes -= session->body_size + sizeof(*session->saved_request);
    ankah_post_payload_release(session->payload);
    session->payload = NULL;
    session->saved_request = NULL;
    session->body = NULL;
    session->body_size = 0;
    session->received = 0;
    session->token[0] = 0;
    session->consumption_pending = 0;
    ++mutation;
}

void ankah_session_cancel_post(ankah_session *session) {
    if (session) release_post(session);
}

int ankah_session_reserve_post(ankah_session *session, const char *token, uint64_t now) {
    if (!ankah_session_solved(session, now) || !session->saved_request ||
        now > session->body_until || session->received != session->body_size ||
        !token || strcmp(session->token, token) != 0 ||
        session->consumption_pending) return -1;
    session->consumption_pending = 1;
    return 0;
}

void ankah_session_unreserve_post(ankah_session *session) {
    if (session) session->consumption_pending = 0;
}

void ankah_session_discard(ankah_session *session) {
    if (!session) return;
    release_post(session);
    memset(session, 0, sizeof(*session));
    ++mutation;
}

static void expire(ankah_session *session, uint64_t now) {
    if (!session->active) return;
    if ((!session->solved_until && now > session->issued + 300) ||
        (session->solved_until && now > session->solved_until)) {
        ankah_session_discard(session);
        return;
    }
    if (session->saved_request && session->solved_until && now > session->body_until)
        release_post(session);
}

ankah_session *ankah_session_find(const char *id, uint64_t now) {
    size_t i;
    if (!id || strlen(id) != 32) return NULL;
    for (i = 0; i < MAX_SESSIONS; ++i) {
        expire(&sessions[i], now);
        if (sessions[i].active && strcmp(sessions[i].id, id) == 0)
            return &sessions[i];
    }
    return NULL;
}

ankah_session *ankah_session_accept_solved(const char *id, uint64_t now,
                                            const char *target, int is_post) {
    ankah_session *session;
    uint64_t issued = 0;
    size_t i;
    if (!id || strlen(id) != 32 || (target && strlen(target) >= ANKAH_MAX_TARGET))
        return NULL;
    for (i = 0; i < 32; ++i) {
        int digit;
        if (id[i] >= '0' && id[i] <= '9') digit = id[i] - '0';
        else if (id[i] >= 'a' && id[i] <= 'f') digit = id[i] - 'a' + 10;
        else return NULL;
        if (i < 8) issued = (issued << 4) | (unsigned int)digit;
    }
    if (issued > now + 30 || now > issued + 1800) return NULL;
    session = ankah_session_find(id, now);
    if (!session) {
        for (i = 0; i < MAX_SESSIONS; ++i) {
            expire(&sessions[i], now);
            if (!sessions[i].active) { session = &sessions[i]; break; }
        }
        if (!session) return NULL;
        memset(session, 0, sizeof(*session));
        strcpy(session->id, id);
        session->issued = issued;
        session->active = 1;
    }
    if (!session->solved_until) {
        session->solved_until = now + 1800;
        session->body_until = now + 300;
    }
    if (target && !session->target[0]) {
        strcpy(session->target, target);
        session->is_post = is_post != 0;
    }
    ++mutation;
    return session;
}

ankah_session *ankah_session_new_with_proof(const unsigned char secret[ANKAH_SECRET_SIZE],
                                            const char *host, uint64_t now,
                                            const ankah_request *request,
                                            const char *peer_ip, int proved) {
    ankah_session *session = NULL;
    size_t i, body_size = 0;
    size_t anonymous_unsolved = 0, anonymous_for_ip = 0;
    int is_post;
    if (!request || !host || !peer_ip) return NULL;
    is_post = strcmp(request->method, "POST") == 0;
    if (is_post) {
        body_size = request->content_length;
        if (body_size > ANKAH_POST_REPLAY_MAX ||
            body_size + sizeof(ankah_request) > MAX_PENDING_BYTES - pending_bytes)
            return NULL;
    }
    for (i = 0; i < MAX_SESSIONS; ++i) {
        expire(&sessions[i], now);
        if (!sessions[i].active && !session) session = &sessions[i];
    }
    if (!session) return NULL;
    if (!proved) {
        for (i = 0; i < MAX_SESSIONS; ++i) {
            ankah_session *candidate = &sessions[i];
            if (!candidate->active || candidate->issued_with_proof ||
                candidate->solved_until) continue;
            ++anonymous_unsolved;
            if (strcmp(candidate->peer_ip, peer_ip) == 0) ++anonymous_for_ip;
        }
        if (anonymous_unsolved >= MAX_ANONYMOUS_UNSOLVED ||
            anonymous_for_ip >= MAX_ANONYMOUS_UNSOLVED_PER_IP) return NULL;
    }
    memset(session, 0, sizeof(*session));
    random_hex(session->id);
    random_hex(session->token);
    if (session->id[0]) {
        char time_hex[9];
        snprintf(time_hex, sizeof(time_hex), "%08" PRIx32, (uint32_t)now);
        memcpy(session->id, time_hex, 8);
    }
    if (!session->id[0] || !session->token[0] ||
        ankah_challenge_for_session(secret, host, now, session->id,
                                    session->challenge) != 0) return NULL;
    strcpy(session->target, request->target);
    strcpy(session->peer_ip, peer_ip);
    session->issued = now;
    session->issued_with_proof = proved != 0;
    session->is_post = is_post;
    if (is_post) {
        session->payload = calloc(1, sizeof(*session->payload));
        if (session->payload) {
            session->payload->request = malloc(sizeof(ankah_request));
            session->payload->body = malloc(body_size ? body_size : 1);
        }
        if (!session->payload || !session->payload->request ||
            !session->payload->body) {
            if (session->payload) {
                free(session->payload->request);
                free(session->payload->body);
                free(session->payload);
            }
            memset(session, 0, sizeof(*session));
            return NULL;
        }
        session->payload->pins = 1;
        session->saved_request = session->payload->request;
        session->body = session->payload->body;
        *session->saved_request = *request;
        session->body_size = body_size;
        pending_bytes += body_size + sizeof(ankah_request);
    }
    session->active = 1;
    ++mutation;
    return session;
}

ankah_session *ankah_session_new(const unsigned char secret[ANKAH_SECRET_SIZE],
                                 const char *host, uint64_t now,
                                 const ankah_request *request, const char *peer_ip) {
    return ankah_session_new_with_proof(secret, host, now, request, peer_ip, 0);
}

int ankah_session_append(ankah_session *session, const void *data, size_t size) {
    if (!session || !session->active || !session->saved_request ||
        size > session->body_size - session->received) return -1;
    if (size) memcpy(session->body + session->received, data, size);
    session->received += size;
    if (size) ++mutation;
    return session->received == session->body_size ? 1 : 0;
}

int ankah_session_solve(ankah_session *session, uint64_t now) {
    if (!session || !session->active || now > session->issued + 300) return -1;
    session->solved_until = now + 1800;
    session->body_until = now + 300;
    ++mutation;
    return 0;
}

int ankah_session_solved(const ankah_session *session, uint64_t now) {
    return session && session->active && session->solved_until >= now &&
           session->solved_until != 0;
}

int ankah_session_take_post(ankah_session *session, const char *token, uint64_t now,
                             ankah_request **request, unsigned char **body,
                             size_t *size, ankah_post_payload **payload) {
    if (!ankah_session_solved(session, now) || !session->saved_request ||
        now > session->body_until || session->received != session->body_size ||
        !token || strcmp(session->token, token) != 0) return -1;
    *request = session->saved_request;
    *body = session->body;
    *size = session->body_size;
    *payload = session->payload;
    pending_bytes -= session->body_size + sizeof(*session->saved_request);
    session->saved_request = NULL;
    session->body = NULL;
    session->payload = NULL;
    session->body_size = 0;
    session->token[0] = 0;
    session->consumption_pending = 0;
    ++mutation;
    return 0;
}

int ankah_session_changed(void) { return mutation != queued_mutation; }

void ankah_session_snapshot_retry(void) { ++mutation; }

#define SESSION_SNAPSHOT_MAX ANKAH_SESSION_SNAPSHOT_MAX
#define SESSION_SNAPSHOT_VERSION 1U

typedef struct {
    char magic[8];
    uint32_t version;
    uint32_t request_size;
    uint32_t record_size;
    uint32_t count;
    uint64_t generation;
    uint64_t size;
} session_snapshot_header;

typedef struct {
    char id[33], token[33], challenge[ANKAH_CHALLENGE_TEXT_MAX];
    char target[ANKAH_MAX_TARGET], peer_ip[64];
    uint64_t issued, solved_until, body_until;
    uint32_t is_post, issued_with_proof, has_payload;
    uint32_t body_size, received;
} session_snapshot_record;

typedef struct {
    session_snapshot_record record;
    ankah_post_payload *payload;
} snapshot_entry;

struct ankah_session_snapshot {
    snapshot_entry *entries;
    unsigned char *data;
    size_t size, used, count, entry, part_used;
    int part;
    uint64_t generation, captured_mutation;
    mbedtls_sha256_context hash;
    int hash_started, complete;
};

ankah_session_snapshot *ankah_session_snapshot_begin(uint64_t now) {
    static const char magic[8] = {'A','N','K','H','S','E','S','S'};
    ankah_session_snapshot *snapshot;
    session_snapshot_header header;
    size_t i;
    snapshot = calloc(1, sizeof(*snapshot));
    if (!snapshot) return NULL;
    snapshot->entries = calloc(MAX_SESSIONS, sizeof(*snapshot->entries));
    if (!snapshot->entries) { free(snapshot); return NULL; }
    snapshot->size = sizeof(header) + 32;
    for (i = 0; i < MAX_SESSIONS; ++i) {
        ankah_session *session = &sessions[i];
        snapshot_entry *entry;
        session_snapshot_record *record;
        expire(session, now);
        if (!session->active || (session->saved_request &&
            session->received != session->body_size)) continue;
        entry = &snapshot->entries[snapshot->count++];
        record = &entry->record;
        memcpy(record->id, session->id, sizeof(record->id));
        memcpy(record->token, session->token, sizeof(record->token));
        memcpy(record->challenge, session->challenge, sizeof(record->challenge));
        memcpy(record->target, session->target, sizeof(record->target));
        memcpy(record->peer_ip, session->peer_ip, sizeof(record->peer_ip));
        record->issued = session->issued;
        record->solved_until = session->solved_until;
        record->body_until = session->body_until;
        record->is_post = (uint32_t)session->is_post;
        record->issued_with_proof = (uint32_t)session->issued_with_proof;
        if (session->payload) {
            record->has_payload = 1;
            record->body_size = (uint32_t)session->body_size;
            record->received = (uint32_t)session->received;
            entry->payload = session->payload;
            ++entry->payload->pins;
            snapshot->size += sizeof(ankah_request) + session->received;
        }
        snapshot->size += sizeof(*record);
    }
    if (snapshot->size > SESSION_SNAPSHOT_MAX) {
        ankah_session_snapshot_free(snapshot);
        return NULL;
    }
    snapshot->captured_mutation = mutation;
    snapshot->generation = ++snapshot_generation;
    snapshot->data = malloc(snapshot->size);
    if (!snapshot->data) { ankah_session_snapshot_free(snapshot); return NULL; }
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, magic, sizeof(magic));
    header.version = SESSION_SNAPSHOT_VERSION;
    header.request_size = sizeof(ankah_request);
    header.record_size = sizeof(session_snapshot_record);
    header.count = (uint32_t)snapshot->count;
    header.generation = snapshot->generation;
    header.size = snapshot->size;
    memcpy(snapshot->data, &header, sizeof(header));
    snapshot->used = sizeof(header);
    mbedtls_sha256_init(&snapshot->hash);
    if (mbedtls_sha256_starts(&snapshot->hash, 0) != 0 ||
        mbedtls_sha256_update(&snapshot->hash, snapshot->data, snapshot->used) != 0) {
        ankah_session_snapshot_free(snapshot);
        return NULL;
    }
    snapshot->hash_started = 1;
    return snapshot;
}

int ankah_session_snapshot_step(ankah_session_snapshot *snapshot, size_t budget) {
    if (!snapshot || !budget) return -1;
    if (snapshot->complete) return 1;
    while (budget && snapshot->entry < snapshot->count) {
        snapshot_entry *entry = &snapshot->entries[snapshot->entry];
        const unsigned char *source;
        size_t length, piece;
        if (snapshot->part == 0) {
            source = (const unsigned char *)&entry->record;
            length = sizeof(entry->record);
        } else if (snapshot->part == 1 && entry->payload) {
            source = (const unsigned char *)entry->payload->request;
            length = sizeof(ankah_request);
        } else if (snapshot->part == 2 && entry->payload) {
            source = entry->payload->body;
            length = entry->record.received;
        } else {
            ++snapshot->entry;
            snapshot->part = 0;
            snapshot->part_used = 0;
            continue;
        }
        if (snapshot->part_used == length) {
            ++snapshot->part;
            snapshot->part_used = 0;
            continue;
        }
        piece = length - snapshot->part_used;
        if (piece > budget) piece = budget;
        memcpy(snapshot->data + snapshot->used, source + snapshot->part_used, piece);
        if (mbedtls_sha256_update(&snapshot->hash,
                                  snapshot->data + snapshot->used, piece) != 0) return -1;
        snapshot->used += piece;
        snapshot->part_used += piece;
        budget -= piece;
    }
    if (snapshot->entry != snapshot->count) return 0;
    if (snapshot->used + 32 != snapshot->size ||
        mbedtls_sha256_finish(&snapshot->hash, snapshot->data + snapshot->used) != 0)
        return -1;
    snapshot->complete = 1;
    return 1;
}

unsigned char *ankah_session_snapshot_detach(ankah_session_snapshot *snapshot,
                                              size_t *size, uint64_t *generation) {
    unsigned char *data;
    if (!snapshot || !snapshot->complete) return NULL;
    data = snapshot->data;
    snapshot->data = NULL;
    *size = snapshot->size;
    *generation = snapshot->generation;
    queued_mutation = snapshot->captured_mutation;
    return data;
}

void ankah_session_snapshot_free(ankah_session_snapshot *snapshot) {
    size_t i;
    if (!snapshot) return;
    for (i = 0; i < snapshot->count; ++i)
        ankah_post_payload_release(snapshot->entries[i].payload);
    if (snapshot->hash_started) mbedtls_sha256_free(&snapshot->hash);
    free(snapshot->entries);
    free(snapshot->data);
    free(snapshot);
}

static int valid_image(const unsigned char *data, size_t size, uint64_t *generation) {
    session_snapshot_header header;
    unsigned char digest[32];
    size_t at, i, body_total = 0;
    if (size < sizeof(header) + 32) return 0;
    memcpy(&header, data, sizeof(header));
    if (memcmp(header.magic, "ANKHSESS", 8) != 0 ||
        header.version != SESSION_SNAPSHOT_VERSION ||
        header.request_size != sizeof(ankah_request) ||
        header.record_size != sizeof(session_snapshot_record) ||
        header.count > MAX_SESSIONS || header.size != size || !header.generation ||
        mbedtls_sha256(data, size - 32, digest, 0) != 0 ||
        memcmp(digest, data + size - 32, 32) != 0) return 0;
    at = sizeof(header);
    for (i = 0; i < header.count; ++i) {
        session_snapshot_record record;
        size_t extra;
        if (at + sizeof(record) > size - 32) return 0;
        memcpy(&record, data + at, sizeof(record));
        at += sizeof(record);
        if (record.id[32] || record.token[32] ||
            !memchr(record.challenge, 0, sizeof(record.challenge)) ||
            !memchr(record.target, 0, sizeof(record.target)) ||
            !memchr(record.peer_ip, 0, sizeof(record.peer_ip)) ||
            record.body_size > ANKAH_POST_REPLAY_MAX ||
            record.received > record.body_size ||
            record.is_post > 1 || record.issued_with_proof > 1 ||
            record.has_payload > 1) return 0;
        extra = record.has_payload ? sizeof(ankah_request) + record.received : 0;
        if (extra > size - 32 - at ||
            (record.has_payload && (!record.is_post ||
             record.received != record.body_size ||
             body_total + sizeof(ankah_request) + record.body_size > MAX_PENDING_BYTES)))
            return 0;
        if (record.has_payload) body_total += sizeof(ankah_request) + record.body_size;
        at += extra;
    }
    if (at != size - 32) return 0;
    *generation = header.generation;
    return 1;
}

int ankah_session_snapshot_saved_ids(const unsigned char *data, size_t size,
                                     char ids[][33], size_t capacity,
                                     size_t *count) {
    session_snapshot_header header;
    uint64_t generation;
    size_t at, i, used = 0;
    if (!data || !ids || !count || !valid_image(data, size, &generation)) return -1;
    memcpy(&header, data, sizeof(header));
    at = sizeof(header);
    for (i = 0; i < header.count; ++i) {
        session_snapshot_record record;
        memcpy(&record, data + at, sizeof(record));
        at += sizeof(record);
        if (record.has_payload) {
            if (used == capacity) return -1;
            memcpy(ids[used++], record.id, 33);
            at += sizeof(ankah_request) + record.received;
        }
    }
    *count = used;
    return 0;
}

void ankah_session_discard_saved_posts(void) {
    size_t i;
    for (i = 0; i < MAX_SESSIONS; ++i) release_post(&sessions[i]);
}

static int load_image(const unsigned char *data, size_t size, uint64_t now) {
    session_snapshot_header header;
    size_t at, i;
    (void)size;
    memcpy(&header, data, sizeof(header));
    at = sizeof(header);
    for (i = 0; i < header.count; ++i) {
        session_snapshot_record record;
        ankah_session *session = &sessions[i];
        memcpy(&record, data + at, sizeof(record));
        at += sizeof(record);
        if ((!record.solved_until && now > record.issued + 300) ||
            (record.solved_until && now > record.solved_until)) {
            if (record.has_payload) at += sizeof(ankah_request) + record.received;
            continue;
        }
        memcpy(session->id, record.id, sizeof(session->id));
        memcpy(session->token, record.token, sizeof(session->token));
        memcpy(session->challenge, record.challenge, sizeof(session->challenge));
        memcpy(session->target, record.target, sizeof(session->target));
        memcpy(session->peer_ip, record.peer_ip, sizeof(session->peer_ip));
        session->issued = record.issued;
        session->solved_until = record.solved_until;
        session->body_until = record.body_until;
        session->is_post = (int)record.is_post;
        session->issued_with_proof = (int)record.issued_with_proof;
        session->active = 1;
        if (record.has_payload) {
            ankah_post_payload *payload = calloc(1, sizeof(*payload));
            if (!payload) return -1;
            payload->request = malloc(sizeof(ankah_request));
            payload->body = malloc(record.body_size ? record.body_size : 1);
            if (!payload->request || !payload->body) {
                free(payload->request); free(payload->body); free(payload);
                return -1;
            }
            payload->pins = 1;
            memcpy(payload->request, data + at, sizeof(ankah_request));
            at += sizeof(ankah_request);
            memcpy(payload->body, data + at, record.received);
            at += record.received;
            session->payload = payload;
            session->saved_request = payload->request;
            session->body = payload->body;
            session->body_size = record.body_size;
            session->received = record.received;
            pending_bytes += sizeof(ankah_request) + record.body_size;
        }
    }
    return 0;
}

int ankah_session_restore(const char *path, uint64_t now) {
    unsigned char *data[2] = {NULL, NULL};
    size_t size[2] = {0, 0};
    uint64_t generation[2] = {0, 0};
    int slot, chosen = -1, result = 0;
    for (slot = 0; slot < 2; ++slot) {
        char candidate[520];
        int n = snprintf(candidate, sizeof(candidate), "%s.%d", path, slot);
        int read_result;
        if (n < 0 || (size_t)n >= sizeof(candidate)) { result = -1; continue; }
        read_result = ankah_file_read_optional(candidate, SESSION_SNAPSHOT_MAX, 1,
                                               &data[slot], &size[slot]);
        if (read_result == 0) {
            if (!valid_image(data[slot], size[slot], &generation[slot])) {
                result = -1;
                free(data[slot]); data[slot] = NULL;
            }
        } else if (read_result < 0) result = -1;
    }
    if (data[0]) chosen = 0;
    if (data[1] && (chosen < 0 || generation[1] > generation[0])) chosen = 1;
    if (chosen >= 0) {
        if (load_image(data[chosen], size[chosen], now) != 0) result = -1;
        snapshot_generation = generation[chosen];
    }
    free(data[0]); free(data[1]);
    {
        char journal[528], line[128];
        FILE *file;
        int journal_bad = 0;
        int n = snprintf(journal, sizeof(journal), "%s.journal", path);
        if (n < 0 || (size_t)n >= sizeof(journal)) return -1;
        file = fopen(journal, "rb");
        if (file) {
            while (fgets(line, sizeof(line), file)) {
                ankah_session *session;
                size_t digit;
                if (strlen(line) != 33 || line[32] != '\n') {
                    journal_bad = 1;
                    continue;
                }
                for (digit = 0; digit < 32; ++digit)
                    if (!((line[digit] >= '0' && line[digit] <= '9') ||
                          (line[digit] >= 'a' && line[digit] <= 'f')))
                        journal_bad = 1;
                if (journal_bad) continue;
                line[32] = 0;
                session = ankah_session_find(line, now);
                if (session) release_post(session);
            }
            if (ferror(file)) journal_bad = 1;
            fclose(file);
        } else if (errno != ENOENT) journal_bad = 1;
        if (journal_bad) {
            ankah_session_discard_saved_posts();
            result = -2;
        }
    }
    mutation = queued_mutation = 0;
    return result;
}

void ankah_session_each_solved(uint64_t now,
                               void (*visit)(const ankah_session *, void *), void *owner) {
    size_t i;
    if (!visit) return;
    for (i = 0; i < MAX_SESSIONS; ++i) {
        expire(&sessions[i], now);
        if (ankah_session_solved(&sessions[i], now)) visit(&sessions[i], owner);
    }
}

void ankah_session_count(uint64_t now, ankah_session_totals *out) {
    size_t i;
    memset(out, 0, sizeof(*out));
    out->capacity = MAX_SESSIONS;
    out->pending_capacity = MAX_PENDING_BYTES;
    for (i = 0; i < MAX_SESSIONS; ++i) {
        expire(&sessions[i], now);
        if (!sessions[i].active) continue;
        ++out->active;
        if (ankah_session_solved(&sessions[i], now)) ++out->solved;
        if (sessions[i].saved_request) ++out->saved_posts;
    }
    out->pending_bytes = pending_bytes;
}
