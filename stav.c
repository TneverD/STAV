#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <time.h>
#include <sys/wait.h>
#include <openssl/evp.h>
#include <curl/curl.h>
#include <jansson.h>

#define API_URL "https://mb-api.abuse.ch/api/v1/"
#define MAX_KEY 512
#define READ_SIZE 262144

static char db_path[PATH_MAX];
static char key_path[PATH_MAX];
static char data_dir[PATH_MAX];
static char names_path[PATH_MAX];
static char cache_path[PATH_MAX];

static unsigned long scanned = 0;
static unsigned long infected = 0;
static unsigned long errors = 0;
static struct timespec scan_started;
static int scan_output_is_tty = 0;

struct Buffer {
    char *data;
    size_t size;
};

static void paths_init(void) {
    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "STAV: HOME is not set.\n");
        exit(1);
    }

    snprintf(data_dir, sizeof(data_dir),
             "%s/.local/share/stav", home);
    snprintf(db_path, sizeof(db_path),
             "%s/malware.sha256", data_dir);
    snprintf(names_path, sizeof(names_path),
             "%s/malware.names", data_dir);
    snprintf(cache_path, sizeof(cache_path),
             "%s/malware.sha256.bin", data_dir);
    snprintf(key_path, sizeof(key_path),
             "%s/.config/stav/api_key", home);

    char config_dir[PATH_MAX];
    snprintf(config_dir, sizeof(config_dir),
             "%s/.config/stav", home);

    mkdir(config_dir, 0700);
    mkdir(data_dir, 0700);
}

static int valid_hash(const char *s) {
    if (!s || strlen(s) != 64) return 0;

    for (int i = 0; i < 64; i++)
        if (!isxdigit((unsigned char)s[i]))
            return 0;

    return 1;
}

static int compare_hash(const void *a, const void *b) {
    return strcmp(*(char * const *)a, *(char * const *)b);
}

static int compare_key(const void *key, const void *element) {
    return strcmp((const char *)key, *(char * const *)element);
}


static void add_hash(char ***list, size_t *count,
                     const char *hash) {
    if (!valid_hash(hash)) return;

    char *copy = strdup(hash);
    if (!copy) return;

    char **tmp = realloc(*list, (*count + 1) * sizeof(char *));
    if (!tmp) {
        free(copy);
        return;
    }

    *list = tmp;
    (*list)[(*count)++] = copy;
}

static void free_hashes(char **list, size_t count) {
    for (size_t i = 0; i < count; i++)
        free(list[i]);
    free(list);
}

static size_t unique_hashes(char **list, size_t count) {
    if (!count) return 0;

    qsort(list, count, sizeof(char *), compare_hash);

    size_t out = 1;

    for (size_t i = 1; i < count; i++) {
        if (strcmp(list[i], list[out - 1]) != 0) {
            list[out++] = list[i];
        } else {
            free(list[i]);
        }
    }

    return out;
}

static void add_hash_grow(char ***list, size_t *count,
                          size_t *capacity, const char *hash) {
    if (!valid_hash(hash)) return;

    if (*count == *capacity) {
        size_t next = *capacity ? *capacity * 2 : 4096;
        if (next < *capacity || next > SIZE_MAX / sizeof(char *))
            return;

        char **tmp = realloc(*list, next * sizeof(char *));
        if (!tmp) return;

        *list = tmp;
        *capacity = next;
    }

    char *copy = strdup(hash);
    if (copy)
        (*list)[(*count)++] = copy;
}

static int load_database(char ***list, size_t *count) {
    *list = NULL;
    *count = 0;
    size_t capacity = 0;

    FILE *f = fopen(db_path, "r");
    if (!f) return 0;

    char *line = NULL;
    size_t cap = 0;
    ssize_t n;

    while ((n = getline(&line, &cap, f)) != -1) {
        while (n > 0 &&
               (line[n - 1] == '\n' ||
                line[n - 1] == '\r' ||
                isspace((unsigned char)line[n - 1]))) {
            line[--n] = '\0';
        }

        if (valid_hash(line))
            add_hash_grow(list, count, &capacity, line);
    }

    free(line);
    fclose(f);

    *count = unique_hashes(*list, *count);
    return 1;
}


/*
 * Fast scanner database:
 * - The human-readable malware.sha256 remains the source of truth.
 * - A compact, sorted 32-byte-per-hash cache is generated when needed.
 * - mmap lets the OS page in only the parts needed by binary search.
 */
#define CACHE_MAGIC "STAVDB01"

struct CacheHeader {
    char magic[8];
    uint64_t source_size;
    int64_t source_mtime_sec;
    int64_t source_mtime_nsec;
    uint64_t count;
};

struct MappedDB {
    int fd;
    void *mapping;
    size_t mapping_size;
    const unsigned char *hashes;
    size_t count;
};

static int hex_to_bytes(const char *hex, unsigned char out[32]) {
    if (!valid_hash(hex)) return 0;

    for (size_t i = 0; i < 32; i++) {
        unsigned int value;
        if (sscanf(hex + (i * 2), "%2x", &value) != 1)
            return 0;
        out[i] = (unsigned char)value;
    }
    return 1;
}

static int cache_is_current(const struct stat *dbst) {
    FILE *f = fopen(cache_path, "rb");
    if (!f) return 0;

    struct CacheHeader h;
    int ok = fread(&h, sizeof(h), 1, f) == 1;
    fclose(f);

    return ok &&
           memcmp(h.magic, CACHE_MAGIC, sizeof(h.magic)) == 0 &&
           h.source_size == (uint64_t)dbst->st_size &&
           h.source_mtime_sec == (int64_t)dbst->st_mtim.tv_sec &&
           h.source_mtime_nsec == (int64_t)dbst->st_mtim.tv_nsec;
}

static int rebuild_binary_cache(const struct stat *dbst) {
    char **list = NULL;
    size_t count = 0;

    if (!load_database(&list, &count))
        return 0;

    char temp[PATH_MAX];
    int n = snprintf(temp, sizeof(temp), "%s.tmp", cache_path);
    if (n < 0 || (size_t)n >= sizeof(temp)) {
        free_hashes(list, count);
        return 0;
    }

    FILE *f = fopen(temp, "wb");
    if (!f) {
        perror("STAV binary cache");
        free_hashes(list, count);
        return 0;
    }

    struct CacheHeader h = {0};
    memcpy(h.magic, CACHE_MAGIC, sizeof(h.magic));
    h.source_size = (uint64_t)dbst->st_size;
    h.source_mtime_sec = (int64_t)dbst->st_mtim.tv_sec;
    h.source_mtime_nsec = (int64_t)dbst->st_mtim.tv_nsec;
    h.count = (uint64_t)count;

    int ok = fwrite(&h, sizeof(h), 1, f) == 1;

    for (size_t i = 0; ok && i < count; i++) {
        unsigned char raw[32];
        if (!hex_to_bytes(list[i], raw) ||
            fwrite(raw, sizeof(raw), 1, f) != 1)
            ok = 0;
    }

    if (fflush(f) != 0) ok = 0;
    if (ok && fsync(fileno(f)) != 0) ok = 0;
    if (fclose(f) != 0) ok = 0;

    if (ok) {
        chmod(temp, 0600);
        if (rename(temp, cache_path) != 0) {
            perror("STAV cache rename");
            ok = 0;
        }
    }

    if (!ok) unlink(temp);
    free_hashes(list, count);
    return ok;
}

static int mapped_db_open(struct MappedDB *db) {
    memset(db, 0, sizeof(*db));
    db->fd = -1;

    struct stat dbst;
    if (stat(db_path, &dbst) != 0 || !S_ISREG(dbst.st_mode))
        return 0;

    if (!cache_is_current(&dbst) && !rebuild_binary_cache(&dbst)) {
        fprintf(stderr, "[!] Could not build fast database cache.\n");
        return 0;
    }

    db->fd = open(cache_path, O_RDONLY);
    if (db->fd < 0) return 0;

    struct stat cst;
    if (fstat(db->fd, &cst) != 0 ||
        cst.st_size < (off_t)sizeof(struct CacheHeader)) {
        close(db->fd);
        db->fd = -1;
        return 0;
    }

    db->mapping_size = (size_t)cst.st_size;
    db->mapping = mmap(NULL, db->mapping_size, PROT_READ, MAP_PRIVATE,
                       db->fd, 0);
    if (db->mapping == MAP_FAILED) {
        db->mapping = NULL;
        close(db->fd);
        db->fd = -1;
        return 0;
    }

    const struct CacheHeader *h = db->mapping;
    size_t expected;

    if (memcmp(h->magic, CACHE_MAGIC, sizeof(h->magic)) != 0 ||
        h->count > (SIZE_MAX - sizeof(*h)) / 32) {
        munmap(db->mapping, db->mapping_size);
        close(db->fd);
        db->mapping = NULL;
        db->fd = -1;
        return 0;
    }

    expected = sizeof(*h) + (size_t)h->count * 32;
    if (expected != db->mapping_size) {
        munmap(db->mapping, db->mapping_size);
        close(db->fd);
        db->mapping = NULL;
        db->fd = -1;
        return 0;
    }

    db->hashes = (const unsigned char *)db->mapping + sizeof(*h);
    db->count = (size_t)h->count;
    return 1;
}

static void mapped_db_close(struct MappedDB *db) {
    if (db->mapping)
        munmap(db->mapping, db->mapping_size);
    if (db->fd >= 0)
        close(db->fd);

    memset(db, 0, sizeof(*db));
    db->fd = -1;
}

static int mapped_db_contains(const struct MappedDB *db,
                              const unsigned char hash[32]) {
    size_t low = 0;
    size_t high = db->count;

    while (low < high) {
        size_t mid = low + (high - low) / 2;
        int cmp = memcmp(hash, db->hashes + mid * 32, 32);

        if (cmp == 0) return 1;
        if (cmp < 0) high = mid;
        else low = mid + 1;
    }

    return 0;
}

static int save_database(char **list, size_t count) {
    char temp[PATH_MAX];
    snprintf(temp, sizeof(temp), "%s.tmp", db_path);

    FILE *f = fopen(temp, "w");
    if (!f) {
        perror("STAV database");
        return 0;
    }

    for (size_t i = 0; i < count; i++)
        fprintf(f, "%s\n", list[i]);

    if (fflush(f) != 0) {
        fclose(f);
        unlink(temp);
        return 0;
    }

    int fd = fileno(f);
    if (fd >= 0) fsync(fd);

    fclose(f);
    chmod(temp, 0600);

    if (rename(temp, db_path) != 0) {
        perror("STAV database rename");
        unlink(temp);
        return 0;
    }

    return 1;
}

static int read_api_key(char *key, size_t size) {
    FILE *f = fopen(key_path, "r");
    if (!f) return 0;

    if (!fgets(key, size, f)) {
        fclose(f);
        return 0;
    }

    fclose(f);

    key[strcspn(key, "\r\n")] = 0;
    return key[0] != '\0';
}

static int configure(void) {
    char key[MAX_KEY];

    printf("\nSTAV API Configuration\n");
    printf("Get your free key from https://auth.abuse.ch/\n");
    printf("Enter API key: ");

    if (!fgets(key, sizeof(key), stdin))
        return 0;

    key[strcspn(key, "\r\n")] = 0;

    if (strlen(key) < 10) {
        printf("Invalid or empty API key.\n");
        return 0;
    }

    FILE *f = fopen(key_path, "w");
    if (!f) {
        perror("Cannot save API key");
        return 0;
    }

    fprintf(f, "%s\n", key);
    fclose(f);
    chmod(key_path, 0600);

    printf("API key saved securely.\n");
    return 1;
}

static size_t write_callback(void *ptr, size_t size,
                             size_t nmemb, void *userdata) {
    struct Buffer *b = userdata;
    size_t bytes = size * nmemb;

    if (bytes > SIZE_MAX - b->size - 1)
        return 0;

    char *tmp = realloc(b->data, b->size + bytes + 1);
    if (!tmp) return 0;

    b->data = tmp;
    memcpy(b->data + b->size, ptr, bytes);

    b->size += bytes;
    b->data[b->size] = '\0';

    return bytes;
}

static void print_size(size_t bytes) {
    if (bytes >= 1024 * 1024)
        printf("%.2f MB", (double)bytes / (1024.0 * 1024.0));
    else if (bytes >= 1024)
        printf("%.2f KB", (double)bytes / 1024.0);
    else
        printf("%zu bytes", bytes);
}

static int fetch_recent(char ***fresh, size_t *fresh_count,
                        size_t *response_size) {
    char key[MAX_KEY];

    *fresh = NULL;
    *fresh_count = 0;
    *response_size = 0;

    if (!read_api_key(key, sizeof(key))) {
        printf("\n[!] MalwareBazaar API key is not configured.\n");
        printf("[!] Run: stav configure\n");
        return 0;
    }

    struct Buffer response = {0};

    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    struct curl_slist *headers = NULL;
    char auth_header[MAX_KEY + 32];

    snprintf(auth_header, sizeof(auth_header),
             "Auth-Key: %s", key);

    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers,
                                "Content-Type: application/x-www-form-urlencoded");

    curl_easy_setopt(curl, CURLOPT_URL, API_URL);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,
                     "query=get_recent&selector=100");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "STAV/1.0");

    CURLcode result = curl_easy_perform(curl);
    long status = 0;

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (result != CURLE_OK || status != 200 || !response.data) {
        printf("[!] MalwareBazaar connection failed: %s\n",
               result != CURLE_OK ?
               curl_easy_strerror(result) : "HTTP error");
        free(response.data);
        return 0;
    }

    json_error_t error;
    json_t *root = json_loadb(response.data, response.size,
                              0, &error);

    if (!root) {
        printf("[!] Invalid API response.\n");
        free(response.data);
        return 0;
    }

    json_t *query_status = json_object_get(root, "query_status");

    if (!json_is_string(query_status) ||
        strcmp(json_string_value(query_status), "ok") != 0) {
        printf("[!] API response: %s\n",
               json_is_string(query_status) ?
               json_string_value(query_status) : "unknown error");
        json_decref(root);
        free(response.data);
        return 0;
    }

    json_t *data = json_object_get(root, "data");

    if (json_is_array(data)) {
        size_t index;
        json_t *item;

        json_array_foreach(data, index, item) {
            json_t *hash = json_object_get(item, "sha256_hash");

            if (json_is_string(hash))
                add_hash(fresh, fresh_count,
                         json_string_value(hash));
        }
    }

    *fresh_count = unique_hashes(*fresh, *fresh_count);
    *response_size = response.size;

    json_decref(root);
    free(response.data);

    return 1;
}

static int ask_yes_no(void) {
    char answer[32];

    printf("Download and install database update? [y/N]: ");

    if (!fgets(answer, sizeof(answer), stdin))
        return 0;

    return answer[0] == 'y' || answer[0] == 'Y';
}

static void update_check(void) {
    struct stat st;
    int db_exists = stat(db_path, &st) == 0;

    char **old = NULL;
    size_t old_count = 0;

    if (db_exists)
        load_database(&old, &old_count);

    printf("\n==================================\n");
    printf(" STAV DATABASE UPDATE CHECK\n");
    printf("==================================\n");

    if (!db_exists) {
        printf("[!] Database not found!\n");
        printf("[!] You must download the database before scanning.\n");
    } else {
        printf("[+] Local database: ");
        print_size((size_t)st.st_size);
        printf(" | %zu hashes\n", old_count);
    }

    char **fresh = NULL;
    size_t fresh_count = 0;
    size_t response_size = 0;

    if (!fetch_recent(&fresh, &fresh_count, &response_size)) {
        if (!db_exists)
            printf("[!] Database download is required.\n");

        free_hashes(old, old_count);
        return;
    }

    size_t new_count = 0;

    for (size_t i = 0; i < fresh_count; i++) {
        if (!bsearch(fresh[i], old, old_count,
                     sizeof(char *), compare_key)) {
            new_count++;
        }
    }

    if (!db_exists || new_count > 0) {
        printf("\n[+] Database update available!\n");
        printf("[+] New hashes: %zu\n", new_count);
        printf("[+] Update download size: ");
        print_size(response_size);
        printf("\n");

        if (ask_yes_no()) {
            for (size_t i = 0; i < fresh_count; i++)
                add_hash(&old, &old_count, fresh[i]);

            old_count = unique_hashes(old, old_count);

            if (save_database(old, old_count)) {
                printf("\n[+] Database successfully updated!\n");
                printf("[+] Total hashes: %zu\n", old_count);
            } else {
                printf("[!] Database update failed.\n");
            }
        } else {
            printf("[!] Update postponed.\n");
        }
    } else {
        printf("\n[+] Database is up to date.\n");
        printf("[+] No new hashes in the latest 100 samples.\n");
    }

    free_hashes(fresh, fresh_count);
    free_hashes(old, old_count);
}

static int hash_file(const char *path, unsigned char output[32]) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fclose(f);
        return 0;
    }

    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    unsigned char buffer[READ_SIZE];
    size_t n;

    while (ok && (n = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, n) != 1)
            ok = 0;
    }

    if (ferror(f)) ok = 0;

    unsigned int digest_len = 0;
    if (ok)
        ok = EVP_DigestFinal_ex(ctx, output, &digest_len) == 1 &&
             digest_len == 32;

    EVP_MD_CTX_free(ctx);
    fclose(f);
    return ok;
}

static void hash_to_hex(const unsigned char hash[32], char output[65]) {
    static const char hex[] = "0123456789abcdef";

    for (size_t i = 0; i < 32; i++) {
        output[i * 2] = hex[hash[i] >> 4];
        output[i * 2 + 1] = hex[hash[i] & 0x0f];
    }
    output[64] = '\0';
}

static int skipped_system_path(const char *path) {
    const char *skip[] = {
        "/proc", "/sys", "/dev", "/run",
        "/media", "/mnt", NULL
    };

    for (int i = 0; skip[i]; i++) {
        size_t n = strlen(skip[i]);

        if (strncmp(path, skip[i], n) == 0 &&
            (path[n] == '\0' || path[n] == '/'))
            return 1;
    }

    return 0;
}


static void print_malware_name(const char *hash) {
    FILE *f = fopen(names_path, "r");

    if (!f) {
        printf("Name: Unknown (not in names database)\n");
        return;
    }

    char *line = NULL;
    size_t capacity = 0;
    ssize_t length;
    int found = 0;

    while ((length = getline(&line, &capacity, f)) != -1) {
        while (length > 0 &&
               (line[length - 1] == '\n' ||
                line[length - 1] == '\r')) {
            line[--length] = '\0';
        }

        char *tab = strchr(line, '\t');

        if (!tab)
            continue;

        *tab = '\0';
        char *name = tab + 1;

        if (strcmp(line, hash) == 0) {
            printf("Name: %s\n",
                   *name ? name : "Unknown");
            found = 1;
            break;
        }
    }

    if (!found)
        printf("Name: Unknown (not in names database)\n");

    free(line);
    fclose(f);
}

static double scan_elapsed_seconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0.0;

    return (double)(now.tv_sec - scan_started.tv_sec) +
           (double)(now.tv_nsec - scan_started.tv_nsec) / 1000000000.0;
}

static void print_scan_progress(const char *path) {
    unsigned long processed = scanned + errors;
    double elapsed = scan_elapsed_seconds();
    double rate = elapsed > 0.0 ? (double)processed / elapsed : 0.0;
    char short_path[96];
    size_t length = strlen(path);

    if (length < sizeof(short_path)) {
        memcpy(short_path, path, length + 1);
    } else {
        snprintf(short_path, sizeof(short_path), "...%s",
                 path + length - (sizeof(short_path) - 4));
    }

    if (scan_output_is_tty) {
        printf("\r\033[2K[STAV] Files: %lu | Threats: %lu | Errors: %lu | %.1f files/s | %s",
               processed, infected, errors, rate, short_path);
        fflush(stdout);
    } else if (processed > 0 && processed % 100 == 0) {
        printf("[STAV] Files: %lu | Threats: %lu | Errors: %lu | %.1f files/s | %s\n",
               processed, infected, errors, rate, short_path);
        fflush(stdout);
    }
}

static void scan_file(const char *path, const struct MappedDB *db) {
    unsigned char raw_hash[32];

    /* Show the current file immediately, even if hashing takes time. */
    print_scan_progress(path);

    if (!hash_file(path, raw_hash)) {
        errors++;
        print_scan_progress(path);
        return;
    }

    scanned++;

    if (mapped_db_contains(db, raw_hash)) {
        char hash[65];
        hash_to_hex(raw_hash, hash);
        if (scan_output_is_tty)
            printf("\r\033[2K");
        infected++;
        printf("\n[!!!] MALWARE DETECTED!\n");
        printf("File: %s\n", path);
        printf("SHA256: %s\n", hash);
        print_malware_name(hash);
        printf("Status: KNOWN MALWARE\n\n");
    }

    print_scan_progress(path);
}

static void scan_path(const char *path, const struct MappedDB *db) {
    struct stat st;

    if (lstat(path, &st) != 0) {
        errors++;
        return;
    }

    if (S_ISLNK(st.st_mode))
        return;

    if (S_ISREG(st.st_mode)) {
        scan_file(path, db);
        return;
    }

    if (!S_ISDIR(st.st_mode))
        return;

    if (skipped_system_path(path))
        return;

    DIR *dir = opendir(path);
    if (!dir) {
        errors++;
        return;
    }

    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        if (!strcmp(entry->d_name, ".") ||
            !strcmp(entry->d_name, ".."))
            continue;

        char full[PATH_MAX];

        int n = snprintf(full, sizeof(full),
                         "%s/%s", path, entry->d_name);

        if (n < 0 || (size_t)n >= sizeof(full)) {
            errors++;
            continue;
        }

        scan_path(full, db);
    }

    closedir(dir);
}

static void run_scan(const char *path) {
    struct MappedDB db;

    if (!mapped_db_open(&db)) {
        printf("\n[!] STAV database is missing or could not be opened.\n");
        printf("[!] Run: stav update\n");
        return;
    }

    if (db.count == 0) {
        printf("[!] Database is empty.\n");
        mapped_db_close(&db);
        return;
    }

    scanned = 0;
    infected = 0;
    errors = 0;
    scan_output_is_tty = isatty(STDOUT_FILENO);
    clock_gettime(CLOCK_MONOTONIC, &scan_started);

    printf("\n==================================\n");
    printf(" STAV SCANNER\n");
    printf("==================================\n");
    printf("Target: %s\n", path);
    printf("Database hashes: %zu (memory-mapped)\n\n", db.count);

    scan_path(path, &db);

    if (scan_output_is_tty)
        printf("\r\033[2K");

    printf("\n==================================\n");
    printf(" SCAN REPORT\n");
    printf("==================================\n");
    printf("Scanned files : %lu\n", scanned);
    printf("Threats found : %lu\n", infected);
    printf("Read errors   : %lu\n", errors);
    printf("Elapsed time  : %.2f seconds\n", scan_elapsed_seconds());
    if (scan_elapsed_seconds() > 0.0)
        printf("Scan speed    : %.1f files/second\n",
               (double)(scanned + errors) / scan_elapsed_seconds());

    if (infected)
        printf("\n[!] WARNING: Known malware detected!\n");
    else
        printf("\n[+] No known malware found.\n");

    printf("[i] This is hash-based detection, not a full malware analysis.\n");

    mapped_db_close(&db);
}

static void quick_scan(void) {
    const char *home = getenv("HOME");
    char downloads[PATH_MAX];
    char desktop[PATH_MAX];
    char documents[PATH_MAX];

    snprintf(downloads, sizeof(downloads),
             "%s/Downloads", home);
    snprintf(desktop, sizeof(desktop),
             "%s/Desktop", home);
    snprintf(documents, sizeof(documents),
             "%s/Documents", home);

    printf("\n[STAV] Quick scan started...\n");

    run_scan(downloads);
    run_scan(desktop);
    run_scan(documents);
    run_scan("/tmp");
    run_scan("/var/tmp");
}

static void show_status(void) {
    struct stat st;
    char **db = NULL;
    size_t count = 0;

    if (load_database(&db, &count)) {
        stat(db_path, &st);
        printf("\nSTAV DATABASE STATUS\n");
        printf("Hashes: %zu\n", count);
        printf("Size: ");
        print_size((size_t)st.st_size);
        printf("\n");
        free_hashes(db, count);
    } else {
        printf("\nDatabase: NOT INSTALLED\n");
    }

    char key[MAX_KEY];
    printf("API key: %s\n",
           read_api_key(key, sizeof(key)) ?
           "Configured" : "Not configured");
}

static void menu(void) {
    char input[PATH_MAX];

    while (1) {
        printf("\n");
        printf("==================================\n");
        printf("       STAV ANTIVIRUS 1.0\n");
        printf("    Super Tiny Anti Virus\n");
        printf("==================================\n");
        printf("1. Quick Scan\n");
        printf("2. Scan a file\n");
        printf("3. Scan a folder\n");
        printf("4. Scan entire system\n");
        printf("5. Update database\n");
        printf("6. Database status\n");
        printf("7. Configure API key\n");
        printf("0. Exit\n");
        printf("----------------------------------\n");
        printf("Select: ");

        if (!fgets(input, sizeof(input), stdin))
            break;

        switch (atoi(input)) {
            case 1:
                quick_scan();
                break;

            case 2:
                printf("File path: ");
                if (fgets(input, sizeof(input), stdin)) {
                    input[strcspn(input, "\r\n")] = 0;
                    if (*input) run_scan(input);
                }
                break;

            case 3:
                printf("Folder path: ");
                if (fgets(input, sizeof(input), stdin)) {
                    input[strcspn(input, "\r\n")] = 0;
                    if (*input) run_scan(input);
                }
                break;

            case 4:
                run_scan("/");
                break;

            case 5:
                update_check();
                break;

            case 6:
                show_status();
                break;

            case 7:
                configure();
                break;

            case 0:
                printf("STAV shutting down.\n");
                return;

            default:
                printf("Invalid option.\n");
        }
    }
}

static int executable_exists(const char *path) {
    return access(path, X_OK) == 0;
}

/* Launch the interactive menu in a dedicated fullscreen terminal window.
 * Explicit commands such as "stav scan PATH" stay in the caller's terminal.
 */
static int launch_fullscreen_terminal(const char *argv0) {
    if (getenv("STAV_FULLSCREEN_CHILD") || getenv("STAV_NO_FULLSCREEN"))
        return 0;

    /* Do not try to open a graphical terminal in a headless SSH session. */
    if (!getenv("DISPLAY") && !getenv("WAYLAND_DISPLAY"))
        return 0;

    char executable[PATH_MAX];
    ssize_t length = readlink("/proc/self/exe", executable,
                              sizeof(executable) - 1);
    if (length <= 0 || (size_t)length >= sizeof(executable) - 1) {
        (void)argv0;
        return 0;
    }
    executable[length] = '\0';

    const char *terminal = NULL;
    int terminal_type = 0;
    if (executable_exists("/usr/bin/gnome-terminal")) {
        terminal = "/usr/bin/gnome-terminal";
        terminal_type = 1;
    } else if (executable_exists("/usr/bin/xfce4-terminal")) {
        terminal = "/usr/bin/xfce4-terminal";
        terminal_type = 2;
    } else if (executable_exists("/usr/bin/mate-terminal")) {
        terminal = "/usr/bin/mate-terminal";
        terminal_type = 3;
    } else if (executable_exists("/usr/bin/konsole")) {
        terminal = "/usr/bin/konsole";
        terminal_type = 4;
    } else if (executable_exists("/usr/bin/xterm")) {
        terminal = "/usr/bin/xterm";
        terminal_type = 5;
    }

    if (!terminal)
        return 0;

    pid_t pid = fork();
    if (pid < 0)
        return 0;

    if (pid == 0) {
        setenv("STAV_FULLSCREEN_CHILD", "1", 1);

        if (terminal_type == 1 || terminal_type == 3)
            execl(terminal, terminal, "--full-screen", "--", executable,
                  (char *)NULL);
        else if (terminal_type == 2)
            execl(terminal, terminal, "--fullscreen", "--command", executable,
                  (char *)NULL);
        else if (terminal_type == 4)
            execl(terminal, terminal, "--fullscreen", "-e", executable,
                  (char *)NULL);
        else
            execl(terminal, terminal, "-fullscreen", "-e", executable,
                  (char *)NULL);

        _exit(127);
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return 0;
    }

    /* 127 means the terminal command itself could not be executed. */
    if (WIFEXITED(status) && WEXITSTATUS(status) == 127)
        return 0;

    return 1;
}

/* Keep the dedicated fullscreen terminal visible after STAV exits.
 * This also runs for ordinary exit() paths, including startup errors.
 * Direct CLI commands in the user's existing terminal are not paused.
 */
static void keep_fullscreen_terminal_open(void) {
    const char *child = getenv("STAV_FULLSCREEN_CHILD");
    if (!child || strcmp(child, "1") != 0 || !isatty(STDIN_FILENO))
        return;

    printf("\n[STAV] Finished. Press ENTER to close this window...");
    fflush(stdout);

    int ch;
    do {
        ch = getchar();
    } while (ch != '\n' && ch != EOF);
}

int main(int argc, char **argv) {
    /* Registered first so even early startup failures leave the window open. */
    atexit(keep_fullscreen_terminal_open);
    if (argc == 1 && launch_fullscreen_terminal(argv[0]))
        return 0;

    paths_init();

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        fprintf(stderr, "Cannot initialize networking.\n");
        return 1;
    }

    printf("\n");
    printf("==================================\n");
    printf(" STAV - Super Tiny Anti Virus\n");
    printf(" Version 1.0\n");
    printf("==================================\n");

    if (argc > 1 && !strcmp(argv[1], "configure")) {
        configure();
        curl_global_cleanup();
        return 0;
    }

    if (argc > 1 && (!strcmp(argv[1], "--help") ||
                     !strcmp(argv[1], "-h"))) {
        printf("Usage:\n");
        printf(" stav                 Interactive menu\n");
        printf(" stav configure       Set MalwareBazaar API key\n");
        printf(" stav scan FILE       Scan a file or folder\n");
        printf(" stav quick           Quick scan\n");
        printf(" stav full            Full root filesystem scan\n");
        printf(" stav update          Check database updates\n");
        printf(" stav status          Database status\n");
        curl_global_cleanup();
        return 0;
    }

    if (argc > 1) {
        if (!strcmp(argv[1], "scan")) {
            if (argc < 3)
                printf("Usage: stav scan PATH\n");
            else
                run_scan(argv[2]);
        } else if (!strcmp(argv[1], "quick")) {
            quick_scan();
        } else if (!strcmp(argv[1], "full")) {
            run_scan("/");
        } else if (!strcmp(argv[1], "update")) {
            update_check();
            printf("Update check completed.\n");
        } else if (!strcmp(argv[1], "status")) {
            show_status();
        } else {
            printf("Unknown command. Try: stav --help\n");
        }
    } else {
        menu();
    }

    curl_global_cleanup();
    return 0;
}
