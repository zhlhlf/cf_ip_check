#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <pthread.h>
#include <curl/curl.h>
#include <sys/stat.h>

#define MAX_CIDRS 4096
#define MAX_IPS 10000
#define MAX_RESULTS 10000
#define MAX_LINE_LEN 16384

typedef struct {
    char *data;
    size_t size;
} MemoryBuffer;

typedef struct {
    uint32_t network;
    int prefix;
    uint32_t host_count;
    char cidr_str[64];
} CIDR;

typedef struct {
    char ip[64];
    int port;
    double timeout;
    int success;
    double delay_ms;
} TaskResult;

typedef struct {
    TaskResult *tasks;
    int total_tasks;
    int next_index;
    pthread_mutex_t lock;
} TaskQueue;

typedef struct {
    TaskQueue *queue;
} WorkerArg;

typedef struct {
    char ip[64];
} BestNode;

static const char *fallback_cidrs[] = {
    "108.162.198.0/24",
    "172.64.144.0/22",
    "104.18.32.0/20",
    "162.159.32.0/20",
    "173.245.58.0/23",
    "104.26.0.0/20"
};

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t real_size = size * nmemb;
    MemoryBuffer *mem = (MemoryBuffer *)userp;

    char *ptr = realloc(mem->data, mem->size + real_size + 1);
    if (!ptr) return 0;

    mem->data = ptr;
    memcpy(mem->data + mem->size, contents, real_size);
    mem->size += real_size;
    mem->data[mem->size] = '\0';

    return real_size;
}

int fetch_url(const char *url, char **output) {
    CURL *curl;
    CURLcode res;
    MemoryBuffer chunk;

    chunk.data = malloc(1);
    if (!chunk.data) return -1;
    chunk.data[0] = '\0';
    chunk.size = 0;

    curl = curl_easy_init();
    if (!curl) {
        free(chunk.data);
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "cf-ip-select/1.0");

    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        free(chunk.data);
        return -1;
    }

    *output = chunk.data;
    return 0;
}

int parse_cidr(const char *cidr_str, CIDR *cidr) {
    char ip_part[64];
    int prefix;
    const char *slash = strchr(cidr_str, '/');
    if (!slash) return -1;

    size_t ip_len = slash - cidr_str;
    if (ip_len >= sizeof(ip_part)) return -1;

    strncpy(ip_part, cidr_str, ip_len);
    ip_part[ip_len] = '\0';

    prefix = atoi(slash + 1);
    if (prefix < 0 || prefix > 32) return -1;

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_part, &addr) != 1) return -1;

    uint32_t ip = ntohl(addr.s_addr);
    uint32_t mask = (prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - prefix));
    uint32_t network = ip & mask;

    uint64_t num_addresses64 = (prefix == 32) ? 1ULL : (1ULL << (32 - prefix));
    uint32_t host_count;
    if (num_addresses64 <= 2) {
        host_count = (uint32_t)num_addresses64;
    } else if (num_addresses64 > 0xFFFFFFFFULL) {
        host_count = 0xFFFFFFFFU;
    } else {
        host_count = (uint32_t)(num_addresses64 - 2);
    }

    cidr->network = network;
    cidr->prefix = prefix;
    cidr->host_count = host_count;
    strncpy(cidr->cidr_str, cidr_str, sizeof(cidr->cidr_str) - 1);
    cidr->cidr_str[sizeof(cidr->cidr_str) - 1] = '\0';

    return 0;
}

void ip_to_string(uint32_t ip, char *buf, size_t buf_size) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    inet_ntop(AF_INET, &addr, buf, buf_size);
}

uint32_t random_ip_from_cidr(CIDR *cidr) {
    uint64_t num_addresses = (cidr->prefix == 32) ? 1ULL : (1ULL << (32 - cidr->prefix));
    if (num_addresses <= 2) {
        return cidr->network;
    }

    uint32_t range = (uint32_t)(num_addresses - 2);
    uint32_t host_offset = 1 + (uint32_t)(rand() % range);
    return cidr->network + host_offset;
}

int load_cidrs(const char *url, CIDR *cidrs, int max_cidrs) {
    char *content = NULL;
    int count = 0;

    if (fetch_url(url, &content) == 0) {
        char *saveptr;
        char *line = strtok_r(content, "\n", &saveptr);
        while (line && count < max_cidrs) {
            while (*line == ' ' || *line == '\t') line++;
            if (*line && *line != '#') {
                char clean[64];
                snprintf(clean, sizeof(clean), "%s", line);
                clean[strcspn(clean, "\r\n")] = '\0';
                if (parse_cidr(clean, &cidrs[count]) == 0) {
                    count++;
                }
            }
            line = strtok_r(NULL, "\n", &saveptr);
        }
        free(content);

        if (count > 0) {
            printf("✓ 获取到 %d 个CIDR网段\n", count);
            return count;
        }
    }

    printf("✗ 获取CIDR失败，使用备选网段\n");
    for (int i = 0; i < (int)(sizeof(fallback_cidrs) / sizeof(fallback_cidrs[0])) && count < max_cidrs; i++) {
        if (parse_cidr(fallback_cidrs[i], &cidrs[count]) == 0) {
            count++;
        }
    }
    printf("⚠ 使用备选 %d 个CIDR网段\n", count);
    return count;
}

int generate_candidate_ips(CIDR *cidrs, int cidr_count, char ips[][64], int sample_size) {
    if (cidr_count <= 0 || sample_size <= 0) return 0;

    uint64_t total_weight = 0;
    for (int i = 0; i < cidr_count; i++) {
        total_weight += (cidrs[i].host_count > 0 ? cidrs[i].host_count : 1);
    }

    int *quotas = calloc(cidr_count, sizeof(int));
    if (!quotas) return 0;

    int assigned = 0;
    for (int i = 0; i < cidr_count; i++) {
        uint64_t weight = (cidrs[i].host_count > 0 ? cidrs[i].host_count : 1);
        quotas[i] = (int)((sample_size * weight) / total_weight);
        if (quotas[i] < 1) quotas[i] = 1;
        assigned += quotas[i];
    }

    int idx = 0;
    while (assigned < sample_size) {
        quotas[idx % cidr_count]++;
        assigned++;
        idx++;
    }

    int count = 0;
    for (int i = 0; i < cidr_count && count < sample_size; i++) {
        for (int j = 0; j < quotas[i] && count < sample_size; j++) {
            uint32_t ip = random_ip_from_cidr(&cidrs[i]);
            ip_to_string(ip, ips[count], sizeof(ips[count]));
            count++;
        }
    }

    free(quotas);

    for (int i = count - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        char tmp[64];
        strcpy(tmp, ips[i]);
        strcpy(ips[i], ips[j]);
        strcpy(ips[j], tmp);
    }

    return count;
}

double now_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

int tcp_connect_timeout(const char *ip, int port, double timeout_sec, double *delay_ms) {
    int sockfd;
    struct sockaddr_in addr;
    double start, end;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return -1;

    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) {
        close(sockfd);
        return -1;
    }

    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(sockfd);
        return -1;
    }

    start = now_ms();
    int ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS) {
        close(sockfd);
        return -1;
    }

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(sockfd, &wfds);

    struct timeval tv;
    tv.tv_sec = (int)timeout_sec;
    tv.tv_usec = (int)((timeout_sec - (int)timeout_sec) * 1000000);

    ret = select(sockfd + 1, NULL, &wfds, NULL, &tv);
    if (ret <= 0) {
        close(sockfd);
        return -1;
    }

    int so_error = 0;
    socklen_t len = sizeof(so_error);
    if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0) {
        close(sockfd);
        return -1;
    }

    if (so_error != 0) {
        close(sockfd);
        return -1;
    }

    end = now_ms();
    *delay_ms = end - start;
    close(sockfd);
    return 0;
}

void *worker_thread(void *arg) {
    WorkerArg *warg = (WorkerArg *)arg;
    TaskQueue *queue = warg->queue;

    while (1) {
        int idx;

        pthread_mutex_lock(&queue->lock);
        idx = queue->next_index;
        if (idx >= queue->total_tasks) {
            pthread_mutex_unlock(&queue->lock);
            break;
        }
        queue->next_index++;
        pthread_mutex_unlock(&queue->lock);

        TaskResult *task = &queue->tasks[idx];
        double delay;
        if (tcp_connect_timeout(task->ip, task->port, task->timeout, &delay) == 0) {
            task->success = 1;
            task->delay_ms = delay;
        } else {
            task->success = 0;
            task->delay_ms = 1e18;
        }
    }

    return NULL;
}

int compare_results(const void *a, const void *b) {
    const TaskResult *ra = (const TaskResult *)a;
    const TaskResult *rb = (const TaskResult *)b;
    if (ra->delay_ms < rb->delay_ms) return -1;
    if (ra->delay_ms > rb->delay_ms) return 1;
    return 0;
}

int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

void replace_field_value(char *line, size_t size, const char *key, const char *new_value) {
    char *p = strstr(line, key);
    if (!p) return;

    char *val_start = p + strlen(key);
    while (*val_start == ' ') val_start++;

    char *val_end = val_start;
    while (*val_end && *val_end != ',' && *val_end != '}') val_end++;

    char tmp[MAX_LINE_LEN];
    size_t prefix_len = val_start - line;

    snprintf(tmp, sizeof(tmp), "%.*s%s%s",
             (int)prefix_len, line,
             new_value,
             val_end);

    snprintf(line, size, "%s", tmp);
}

void replace_host_header(char *line, size_t size, const char *new_host) {
    char *p = strstr(line, "Host:");
    if (!p) return;

    char *val_start = p + strlen("Host:");
    while (*val_start == ' ') val_start++;

    char *val_end = val_start;
    while (*val_end && *val_end != '}' && *val_end != ',') val_end++;

    char tmp[MAX_LINE_LEN];
    size_t prefix_len = val_start - line;

    snprintf(tmp, sizeof(tmp), "%.*s%s%s",
             (int)prefix_len, line,
             new_host,
             val_end);

    snprintf(line, size, "%s", tmp);
}

void replace_server_port_password_sni(
    const char *line,
    const char *new_ip,
    int new_port,
    const char *password,
    const char *sni,
    char *out,
    size_t out_size,
    int change_port,
    int change_password,
    int change_sni
) {
    snprintf(out, out_size, "%s", line);

    replace_field_value(out, out_size, "server:", new_ip);

    if (change_port) {
        char port_buf[32];
        snprintf(port_buf, sizeof(port_buf), "%d", new_port);
        replace_field_value(out, out_size, "port:", port_buf);
    }

    if (change_password && password && password[0]) {
        replace_field_value(out, out_size, "password:", password);
    }

    if (change_sni && sni && sni[0]) {
        replace_field_value(out, out_size, "sni:", sni);
        replace_host_header(out, out_size, sni);
    }
}

int update_config_yaml(
    const char *filename,
    BestNode *nodes,
    int node_count,
    int new_port,
    const char *password,
    const char *sni,
    int change_port,
    int change_password,
    int change_sni
) {
    if (!file_exists(filename)) {
        printf("⚠ 未找到 %s，跳过配置更新\n", filename);
        return 0;
    }

    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("打开配置文件失败");
        return -1;
    }

    char **lines = NULL;
    int line_count = 0;
    int capacity = 0;
    char buf[MAX_LINE_LEN];

    while (fgets(buf, sizeof(buf), fp)) {
        if (line_count >= capacity) {
            capacity = (capacity == 0) ? 128 : capacity * 2;
            char **tmp = realloc(lines, capacity * sizeof(char *));
            if (!tmp) {
                fclose(fp);
                return -1;
            }
            lines = tmp;
        }

        lines[line_count] = strdup(buf);
        if (!lines[line_count]) {
            fclose(fp);
            for (int i = 0; i < line_count; i++) free(lines[i]);
            free(lines);
            return -1;
        }
        line_count++;
    }
    fclose(fp);

    int replaced = 0;

    for (int i = 0; i < line_count; i++) {
        for (int n = 0; n < node_count && n < 16; n++) {
            char name_pat[64];
            snprintf(name_pat, sizeof(name_pat), "name: CF官方优选%d", n + 1);

            if (strstr(lines[i], name_pat)) {
                char new_line[MAX_LINE_LEN];
                replace_server_port_password_sni(
                    lines[i],
                    nodes[n].ip,
                    new_port,
                    password,
                    sni,
                    new_line,
                    sizeof(new_line),
                    change_port,
                    change_password,
                    change_sni
                );

                free(lines[i]);
                lines[i] = strdup(new_line);
                if (!lines[i]) {
                    for (int k = 0; k < line_count; k++) {
                        if (lines[k]) free(lines[k]);
                    }
                    free(lines);
                    return -1;
                }

                replaced++;
                printf("✓ 已更新 %s -> %s", name_pat, nodes[n].ip);
                if (change_port) printf(":%d", new_port);
                printf("\n");
                break;
            }
        }
    }

    fp = fopen(filename, "w");
    if (!fp) {
        perror("写入配置文件失败");
        for (int i = 0; i < line_count; i++) free(lines[i]);
        free(lines);
        return -1;
    }

    for (int i = 0; i < line_count; i++) {
        fputs(lines[i], fp);
        free(lines[i]);
    }

    free(lines);
    fclose(fp);

    printf("✅ %s 更新完成，共替换 %d 项\n", filename, replaced);
    return replaced;
}

void print_usage(const char *prog) {
    printf("用法:\n");
    printf("  %s [config文件] [端口] [password] [sni]\n", prog);
    printf("\n示例:\n");
    printf("  %s\n", prog);
    printf("  %s config.yaml\n", prog);
    printf("  %s config.yaml 2096\n", prog);
    printf("  %s config.yaml 2096 YOUR_PASSWORD\n", prog);
    printf("  %s config.yaml 2096 YOUR_PASSWORD YOUR_SNI_DOMAIN\n", prog);
}

int main(int argc, char *argv[]) {
    srand((unsigned int)time(NULL));
    curl_global_init(CURL_GLOBAL_DEFAULT);

    const char *config_file = NULL;
    int port = 2096;
    const char *password = NULL;
    const char *sni = NULL;

    int change_file = 0;
    int change_port = 0;
    int change_password = 0;
    int change_sni = 0;

    if (argc >= 2) {
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            print_usage(argv[0]);
            curl_global_cleanup();
            return 0;
        }
        config_file = argv[1];
        change_file = 1;
        change_port = 1;
    }

    if (argc >= 3) {
        port = atoi(argv[2]);
        change_port = 1;
    }

    if (argc >= 4) {
        password = argv[3];
        change_password = 1;
    }

    if (argc >= 5) {
        sni = argv[4];
        change_sni = 1;
    }

    if (argc > 5) {
        print_usage(argv[0]);
        curl_global_cleanup();
        return 1;
    }

    if (port <= 0 || port > 65535) {
        fprintf(stderr, "端口无效\n");
        curl_global_cleanup();
        return 1;
    }

    int count = 16;
    double timeout = 2.0;
    int samples = 512;
    int threads = 50;

    printf("\n🚀 开始优选 - 端口: %d\n", port);
    if (change_file && config_file) {
        printf("📄 目标配置文件: %s\n", config_file);
    } else {
        printf("📄 未指定配置文件，仅打印优选结果\n");
    }
    printf("\n");

    const char *cidr_url = "https://ghfast.top/raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR.txt";

    CIDR cidrs[MAX_CIDRS];
    int cidr_count = load_cidrs(cidr_url, cidrs, MAX_CIDRS);

    char candidate_ips[MAX_IPS][64];
    int ip_count = generate_candidate_ips(cidrs, cidr_count, candidate_ips, samples);
    printf("📡 生成 %d 个候选IP，开始测试...\n\n", ip_count);

    TaskResult tasks[MAX_RESULTS];
    for (int i = 0; i < ip_count; i++) {
        strncpy(tasks[i].ip, candidate_ips[i], sizeof(tasks[i].ip) - 1);
        tasks[i].ip[sizeof(tasks[i].ip) - 1] = '\0';
        tasks[i].port = port;
        tasks[i].timeout = timeout;
        tasks[i].success = 0;
        tasks[i].delay_ms = 1e18;
    }

    TaskQueue queue;
    queue.tasks = tasks;
    queue.total_tasks = ip_count;
    queue.next_index = 0;
    pthread_mutex_init(&queue.lock, NULL);

    pthread_t *tids = malloc(sizeof(pthread_t) * threads);
    if (!tids) {
        fprintf(stderr, "线程内存分配失败\n");
        pthread_mutex_destroy(&queue.lock);
        curl_global_cleanup();
        return 1;
    }

    WorkerArg warg;
    warg.queue = &queue;

    for (int i = 0; i < threads; i++) {
        pthread_create(&tids[i], NULL, worker_thread, &warg);
    }

    for (int i = 0; i < threads; i++) {
        pthread_join(tids[i], NULL);
    }

    free(tids);
    pthread_mutex_destroy(&queue.lock);

    int success_count = 0;
    TaskResult success_results[MAX_RESULTS];

    for (int i = 0; i < ip_count; i++) {
        if (tasks[i].success) {
            printf("✓ %s:%d - %.0fms\n", tasks[i].ip, tasks[i].port, tasks[i].delay_ms);
            success_results[success_count++] = tasks[i];
        } else {
            printf("✗ %s:%d - 超时\n", tasks[i].ip, tasks[i].port);
        }
    }

    qsort(success_results, success_count, sizeof(TaskResult), compare_results);

    if (count > success_count) count = success_count;

    printf("\n✨ 优选结果:\n\n");
    for (int i = 0; i < count; i++) {
        printf("%s:%d# %.0fms\n", success_results[i].ip, success_results[i].port, success_results[i].delay_ms);
    }

    if (change_file && config_file) {
        BestNode best_nodes[16];
        int best_count = (success_count > 16) ? 16 : success_count;

        for (int i = 0; i < best_count; i++) {
            strncpy(best_nodes[i].ip, success_results[i].ip, sizeof(best_nodes[i].ip) - 1);
            best_nodes[i].ip[sizeof(best_nodes[i].ip) - 1] = '\0';
        }

        update_config_yaml(
            config_file,
            best_nodes,
            best_count,
            port,
            password,
            sni,
            change_port,
            change_password,
            change_sni
        );
    }

    curl_global_cleanup();
    return 0;
}