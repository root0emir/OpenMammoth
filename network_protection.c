#include "network_protection.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <pthread.h>
#include <signal.h>
#include <curl/curl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/sysinfo.h>

// Global variables
static ConnectionTracker connections[MAX_CONNECTIONS];
static BlockedIP blocked_ips[MAX_CONNECTIONS];
static int connection_count = 0;
static int blocked_count = 0;
static int protection_level = PROTECTION_MEDIUM;
static bool advanced_protection = true;
static char custom_rules[100][256];
static int custom_rule_count = 0;
static bool is_monitoring = false;
static pthread_t monitoring_thread;
static FILE *log_file = NULL;

// Thread-safe global variables
static pthread_mutex_t connection_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t blocked_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// Performance optimization
#define PACKET_BUFFER_SIZE 65536
#define MAX_THREADS 4
#define BATCH_SIZE 100

// Connection tracking optimization
static ConnectionTracker *connection_pool = NULL;
static int connection_pool_size = 0;
static int connection_pool_index = 0;

// Thread management
static pthread_t worker_threads[MAX_THREADS];
static bool worker_running = true;

// Packet processing queue
typedef struct {
    struct pcap_pkthdr *pkthdr;
    const u_char *packet;
} PacketQueueItem;

static PacketQueueItem packet_queue[PACKET_BUFFER_SIZE];
static int queue_head = 0;
static int queue_tail = 0;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

// Function to log events
void log_event(const char *event_type, const char *ip, const char *message) {
    if (log_file == NULL) {
        log_file = fopen("protection.log", "a");
        if (log_file == NULL) return;
    }
    
    time_t now = time(NULL);
    char *time_str = ctime(&now);
    time_str[strlen(time_str) - 1] = '\0'; // Remove newline
    
    fprintf(log_file, "[%s] %s - IP: %s - %s\n", time_str, event_type, ip, message);
    fflush(log_file);
}

void init_protection() {
    init_connection_pool();
    init_worker_threads();
    load_protection_state();
    
    log_file = fopen("protection.log", "a");
    if (!log_file) {
        perror("Failed to open log file");
        exit(1);
    }
    
    is_monitoring = true;
    log_event("INFO", "SYSTEM", "Protection system initialized");
}

void analyze_packet(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    if (!is_monitoring) return;
    
    struct ip *ip_header = (struct ip *)(packet + 14);
    char source_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);

    if (is_ip_blocked(source_ip)) {
        return;
    }

    // Batch processing optimization
    static int batch_count = 0;
    static struct pcap_pkthdr *batch_pkthdr[BATCH_SIZE];
    static const u_char *batch_packet[BATCH_SIZE];
    static char batch_source_ip[BATCH_SIZE][INET_ADDRSTRLEN];

    batch_pkthdr[batch_count] = (struct pcap_pkthdr *)pkthdr;
    batch_packet[batch_count] = packet;
    strncpy(batch_source_ip[batch_count], source_ip, INET_ADDRSTRLEN);
    batch_count++;

    if (batch_count >= BATCH_SIZE) {
        process_batch(batch_pkthdr, batch_packet, batch_source_ip, batch_count);
        batch_count = 0;
    }
}

int is_ip_blocked(const char *ip) {
    time_t current_time = time(NULL);
    for (int i = 0; i < blocked_count; i++) {
        if (strcmp(blocked_ips[i].ip, ip) == 0) {
            if (current_time < blocked_ips[i].blocked_until) {
                return 1;
            } else {
                unblock_ip(ip);
                return 0;
            }
        }
    }
    return 0;
}

void block_ip(const char *ip, const char *reason, int severity) {
    if (blocked_count >= MAX_CONNECTIONS) return;

    time_t current_time = time(NULL);
    strcpy(blocked_ips[blocked_count].ip, ip);
    strcpy(blocked_ips[blocked_count].reason, reason);
    blocked_ips[blocked_count].severity = severity;
    blocked_ips[blocked_count].blocked_until = current_time + (BLOCK_DURATION * severity);
    blocked_count++;

    printf("IP blocked: %s (Reason: %s, Severity: %d, Duration: %d seconds)\n", 
           ip, reason, severity, BLOCK_DURATION * severity);
}

void unblock_ip(const char *ip) {
    for (int i = 0; i < blocked_count; i++) {
        if (strcmp(blocked_ips[i].ip, ip) == 0) {
            memmove(&blocked_ips[i], &blocked_ips[i + 1], 
                   (blocked_count - i - 1) * sizeof(BlockedIP));
            blocked_count--;
            printf("IP unblocked: %s\n", ip);
            break;
        }
    }
}

void check_ddos_attack() {
    time_t current_time = time(NULL);
    
    for (int i = 0; i < connection_count; i++) {
        double time_diff = difftime(current_time, connections[i].first_seen);
        if (time_diff > 0) {
            double packets_per_second = connections[i].packet_count / time_diff;
            if (packets_per_second > PACKET_THRESHOLD) {
                block_ip(connections[i].source_ip, "DDoS Attack", 5);
            }
        }
    }
}

void check_port_scan(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            if (connections[i].port_scan_count > PORT_SCAN_THRESHOLD) {
                block_ip(source_ip, "Port Scanning", 3);
            }
            break;
        }
    }
}

void check_syn_flood(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            if (connections[i].syn_flood_count > SYN_FLOOD_THRESHOLD) {
                block_ip(source_ip, "SYN Flood Attack", 4);
            }
            break;
        }
    }
}

void check_udp_flood(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            if (connections[i].udp_flood_count > UDP_FLOOD_THRESHOLD) {
                block_ip(source_ip, "UDP Flood Attack", 4);
            }
            break;
        }
    }
}

void check_brute_force(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            if (connections[i].failed_connections > MAX_FAILED_CONNECTIONS) {
                block_ip(source_ip, "Brute Force Attempt", 4);
                log_event("ATTACK", source_ip, "Brute force attack detected");
            }
            break;
        }
    }
}

void check_suspicious_activity(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            int suspicious_count = 0;
            
            if (connections[i].port_scan_count > PORT_SCAN_THRESHOLD / 2) suspicious_count++;
            if (connections[i].syn_flood_count > SYN_FLOOD_THRESHOLD / 2) suspicious_count++;
            if (connections[i].udp_flood_count > UDP_FLOOD_THRESHOLD / 2) suspicious_count++;
            if (connections[i].failed_connections > MAX_FAILED_CONNECTIONS / 2) suspicious_count++;
            
            if (suspicious_count >= SUSPICIOUS_THRESHOLD) {
                connections[i].is_suspicious = true;
                block_ip(source_ip, "Suspicious Activity", 3);
                log_event("SUSPICIOUS", source_ip, "Multiple suspicious activities detected");
            }
            break;
        }
    }
}

void update_thresholds(int ddos, int port_scan, int syn_flood, int udp_flood) {
    if (ddos > 0) PACKET_THRESHOLD = ddos;
    if (port_scan > 0) PORT_SCAN_THRESHOLD = port_scan;
    if (syn_flood > 0) SYN_FLOOD_THRESHOLD = syn_flood;
    if (udp_flood > 0) UDP_FLOOD_THRESHOLD = udp_flood;
    
    log_event("SYSTEM", "0.0.0.0", "Protection thresholds updated");
}

void start_monitoring() {
    if (!is_monitoring) {
        is_monitoring = true;
        log_event("SYSTEM", "0.0.0.0", "Monitoring started");
    }
}

void stop_monitoring() {
    if (is_monitoring) {
        is_monitoring = false;
        log_event("SYSTEM", "0.0.0.0", "Monitoring stopped");
    }
}

void save_protection_state() {
    FILE *state_file = fopen("protection.state", "wb");
    if (state_file == NULL) return;
    
    fwrite(&connection_count, sizeof(int), 1, state_file);
    fwrite(&blocked_count, sizeof(int), 1, state_file);
    fwrite(connections, sizeof(ConnectionTracker), connection_count, state_file);
    fwrite(blocked_ips, sizeof(BlockedIP), blocked_count, state_file);
    
    fclose(state_file);
    log_event("SYSTEM", "0.0.0.0", "Protection state saved");
}

void load_protection_state() {
    FILE *state_file = fopen("protection.state", "rb");
    if (state_file == NULL) return;
    
    fread(&connection_count, sizeof(int), 1, state_file);
    fread(&blocked_count, sizeof(int), 1, state_file);
    fread(connections, sizeof(ConnectionTracker), connection_count, state_file);
    fread(blocked_ips, sizeof(BlockedIP), blocked_count, state_file);
    
    fclose(state_file);
    log_event("SYSTEM", "0.0.0.0", "Protection state loaded");
}

void reset_protection_state() {
    init_protection();
    log_event("SYSTEM", "0.0.0.0", "Protection state reset");
}

// Cleanup function
void cleanup() {
    worker_running = false;
    pthread_cond_broadcast(&queue_cond);
    
    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_join(worker_threads[i], NULL);
    }
    
    pthread_mutex_destroy(&connection_mutex);
    pthread_mutex_destroy(&blocked_mutex);
    pthread_mutex_destroy(&log_mutex);
    pthread_mutex_destroy(&queue_mutex);
    pthread_cond_destroy(&queue_cond);
    
    if (connection_pool) {
        free(connection_pool);
    }
    
    if (log_file) {
        fclose(log_file);
    }
    
    save_protection_state();
}

void print_protection_stats() {
    printf("\n=== Network Protection Statistics ===\n");
    printf("Active connections: %d\n", connection_count);
    printf("Blocked IPs: %d\n", blocked_count);
    printf("Protection level: %d\n", protection_level);
    printf("Advanced protection: %s\n", advanced_protection ? "Enabled" : "Disabled");
    printf("Custom rules: %d\n", custom_rule_count);
    printf("====================================\n\n");
}

void print_blocked_ips() {
    printf("\n=== Blocked IPs ===\n");
    for (int i = 0; i < blocked_count; i++) {
        printf("IP: %s\n", blocked_ips[i].ip);
        printf("Reason: %s\n", blocked_ips[i].reason);
        printf("Severity: %d\n", blocked_ips[i].severity);
        printf("Blocked until: %s", ctime(&blocked_ips[i].blocked_until));
        printf("-------------------\n");
    }
}

void print_connection_stats() {
    printf("\n=== Connection Statistics ===\n");
    for (int i = 0; i < connection_count; i++) {
        printf("IP: %s\n", connections[i].source_ip);
        printf("Packets: %d\n", connections[i].packet_count);
        printf("Port scans: %d\n", connections[i].port_scan_count);
        printf("SYN floods: %d\n", connections[i].syn_flood_count);
        printf("UDP floods: %d\n", connections[i].udp_flood_count);
        printf("Suspicious: %s\n", connections[i].is_suspicious ? "Yes" : "No");
        printf("-------------------\n");
    }
}

void set_protection_level(int level) {
    if (level >= PROTECTION_LOW && level <= PROTECTION_EXTREME) {
        protection_level = level;
        printf("Protection level set to: %d\n", level);
    }
}

void enable_advanced_protection(bool enable) {
    advanced_protection = enable;
    printf("Advanced protection %s\n", enable ? "enabled" : "disabled");
}

void add_custom_rule(const char *rule) {
    if (custom_rule_count < 100) {
        strcpy(custom_rules[custom_rule_count], rule);
        custom_rule_count++;
        printf("Custom rule added: %s\n", rule);
    }
}

void remove_custom_rule(const char *rule) {
    for (int i = 0; i < custom_rule_count; i++) {
        if (strcmp(custom_rules[i], rule) == 0) {
            memmove(&custom_rules[i], &custom_rules[i + 1], 
                   (custom_rule_count - i - 1) * 256);
            custom_rule_count--;
            printf("Custom rule removed: %s\n", rule);
            break;
        }
    }
}

void check_icmp_flood(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            if (connections[i].icmp_count > ICMP_FLOOD_THRESHOLD) {
                block_ip(source_ip, "ICMP Flood Attack", 4);
                log_event("ATTACK", source_ip, "ICMP flood attack detected");
            }
            break;
        }
    }
}

void check_fragment_attack(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            if (connections[i].fragment_count > FRAGMENT_ATTACK_THRESHOLD) {
                block_ip(source_ip, "Fragment Attack", 4);
                log_event("ATTACK", source_ip, "Fragment attack detected");
            }
            break;
        }
    }
}

void check_malformed_packets(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            if (connections[i].malformed_packets > MALFORMED_PACKET_THRESHOLD) {
                block_ip(source_ip, "Malformed Packets", 4);
                log_event("ATTACK", source_ip, "Malformed packets detected");
            }
            break;
        }
    }
}

void check_rate_limiting(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            if (connections[i].rate_limit_count > RATE_LIMIT_THRESHOLD) {
                block_ip(source_ip, "Rate Limit Exceeded", 3);
                log_event("ATTACK", source_ip, "Rate limit exceeded");
            }
            break;
        }
    }
}

void check_geo_location(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            // Burada gerçek bir IP coğrafi konum API'si kullanılabilir
            // Şimdilik örnek olarak bazı ülkeleri engelleyelim
            if (strcmp(connections[i].country_code, "RU") == 0 ||
                strcmp(connections[i].country_code, "CN") == 0 ||
                strcmp(connections[i].country_code, "KP") == 0) {
                block_ip(source_ip, "Geo Blocked Country", 2);
                log_event("GEO", source_ip, "Connection from blocked country");
            }
            break;
        }
    }
}

void check_vpn_tor(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            if (connections[i].is_vpn || connections[i].is_tor) {
                block_ip(source_ip, "VPN/TOR Connection", 2);
                log_event("SECURITY", source_ip, "VPN/TOR connection detected");
            }
            break;
        }
    }
}

void calculate_threat_score(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            int score = 0;
            
            // Port tarama puanı
            if (connections[i].port_scan_count > PORT_SCAN_THRESHOLD / 2) score += 20;
            
            // SYN flood puanı
            if (connections[i].syn_flood_count > SYN_FLOOD_THRESHOLD / 2) score += 20;
            
            // UDP flood puanı
            if (connections[i].udp_flood_count > UDP_FLOOD_THRESHOLD / 2) score += 20;
            
            // ICMP flood puanı
            if (connections[i].icmp_count > ICMP_FLOOD_THRESHOLD / 2) score += 10;
            
            // Fragment attack puanı
            if (connections[i].fragment_count > FRAGMENT_ATTACK_THRESHOLD / 2) score += 10;
            
            // Malformed packets puanı
            if (connections[i].malformed_packets > MALFORMED_PACKET_THRESHOLD / 2) score += 10;
            
            // Rate limiting puanı
            if (connections[i].rate_limit_count > RATE_LIMIT_THRESHOLD / 2) score += 10;
            
            // VPN/TOR puanı
            if (connections[i].is_vpn || connections[i].is_tor) score += 5;
            
            connections[i].threat_score = score;
            
            if (score > THREAT_SCORE_THRESHOLD) {
                block_ip(source_ip, "High Threat Score", 5);
                log_event("THREAT", source_ip, "High threat score detected");
            }
            break;
        }
    }
}

void check_dns_queries(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            if (connections[i].dns_queries > DNS_QUERY_THRESHOLD) {
                block_ip(source_ip, "DNS Query Flood", 3);
                log_event("ATTACK", source_ip, "DNS query flood detected");
            }
            break;
        }
    }
}

void check_http_requests(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            if (connections[i].http_requests > HTTP_REQUEST_THRESHOLD) {
                block_ip(source_ip, "HTTP Request Flood", 3);
                log_event("ATTACK", source_ip, "HTTP request flood detected");
            }
            break;
        }
    }
}

void check_ssl_handshakes(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            if (connections[i].ssl_handshakes > SSL_HANDSHAKE_THRESHOLD) {
                block_ip(source_ip, "SSL Handshake Flood", 3);
                log_event("ATTACK", source_ip, "SSL handshake flood detected");
            }
            break;
        }
    }
}

void check_packet_sizes(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            if (connections[i].packet_size_avg > PACKET_SIZE_THRESHOLD ||
                connections[i].packet_size_max > PACKET_SIZE_THRESHOLD * 2) {
                block_ip(source_ip, "Abnormal Packet Size", 3);
                log_event("ATTACK", source_ip, "Abnormal packet size detected");
            }
            break;
        }
    }
}

void check_tcp_flags(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            for (int j = 0; j < 8; j++) {
                if (connections[i].tcp_flags[j] > TCP_FLAG_THRESHOLD) {
                    block_ip(source_ip, "TCP Flag Anomaly", 3);
                    log_event("ATTACK", source_ip, "TCP flag anomaly detected");
                    break;
                }
            }
            break;
        }
    }
}

void check_udp_ports(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            int port_count = 0;
            for (int j = 0; j < 65536; j++) {
                if (connections[i].udp_ports[j] > 0) {
                    port_count++;
                }
            }
            if (port_count > UDP_PORT_THRESHOLD) {
                block_ip(source_ip, "UDP Port Scan", 3);
                log_event("ATTACK", source_ip, "UDP port scan detected");
            }
            break;
        }
    }
}

void check_icmp_types(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            int type_count = 0;
            for (int j = 0; j < 256; j++) {
                if (connections[i].icmp_types[j] > 0) {
                    type_count++;
                }
            }
            if (type_count > ICMP_TYPE_THRESHOLD) {
                block_ip(source_ip, "ICMP Type Anomaly", 3);
                log_event("ATTACK", source_ip, "ICMP type anomaly detected");
            }
            break;
        }
    }
}

void check_botnet_activity(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            if (connections[i].botnet_activity > BOTNET_THRESHOLD) {
                connections[i].is_botnet = true;
                block_ip(source_ip, "Botnet Activity", 4);
                log_event("ATTACK", source_ip, "Botnet activity detected");
            }
            break;
        }
    }
}

void check_malware_signatures(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            if (connections[i].malware_signatures > MALWARE_THRESHOLD) {
                connections[i].is_malware = true;
                block_ip(source_ip, "Malware Activity", 4);
                log_event("ATTACK", source_ip, "Malware activity detected");
            }
            break;
        }
    }
}

void check_exploit_attempts(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            if (connections[i].exploit_attempts > EXPLOIT_THRESHOLD) {
                connections[i].is_exploit = true;
                block_ip(source_ip, "Exploit Attempt", 4);
                log_event("ATTACK", source_ip, "Exploit attempt detected");
            }
            break;
        }
    }
}

void check_zero_day_attacks(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            if (connections[i].zero_day_attempts > ZERO_DAY_THRESHOLD) {
                block_ip(source_ip, "Zero-Day Attack", 5);
                log_event("ATTACK", source_ip, "Zero-day attack detected");
            }
            break;
        }
    }
}

void check_custom_rules(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            if (connections[i].custom_rule_matches > 0) {
                block_ip(source_ip, "Custom Rule Match", 3);
                log_event("SECURITY", source_ip, "Custom rule match detected");
            }
            break;
        }
    }
}

// Initialize connection pool
static void init_connection_pool() {
    connection_pool_size = MAX_CONNECTIONS;
    connection_pool = (ConnectionTracker *)calloc(connection_pool_size, sizeof(ConnectionTracker));
    if (!connection_pool) {
        log_event("ERROR", "SYSTEM", "Failed to allocate connection pool");
        exit(1);
    }
}

// Get next available connection tracker
static ConnectionTracker* get_next_connection() {
    pthread_mutex_lock(&connection_mutex);
    ConnectionTracker* conn = &connection_pool[connection_pool_index];
    connection_pool_index = (connection_pool_index + 1) % connection_pool_size;
    pthread_mutex_unlock(&connection_mutex);
    return conn;
}

// Worker thread function
static void* worker_thread(void* arg) {
    while (worker_running) {
        pthread_mutex_lock(&queue_mutex);
        while (queue_head == queue_tail && worker_running) {
            pthread_cond_wait(&queue_cond, &queue_mutex);
        }
        
        if (!worker_running) {
            pthread_mutex_unlock(&queue_mutex);
            break;
        }
        
        PacketQueueItem item = packet_queue[queue_head];
        queue_head = (queue_head + 1) % PACKET_BUFFER_SIZE;
        pthread_mutex_unlock(&queue_mutex);
        
        analyze_packet(item.pkthdr, item.packet);
    }
    return NULL;
}

// Initialize worker threads
static void init_worker_threads() {
    for (int i = 0; i < MAX_THREADS; i++) {
        if (pthread_create(&worker_threads[i], NULL, worker_thread, NULL) != 0) {
            log_event("ERROR", "SYSTEM", "Failed to create worker thread");
            exit(1);
        }
    }
}

// Queue packet for processing
static void queue_packet(struct pcap_pkthdr *pkthdr, const u_char *packet) {
    pthread_mutex_lock(&queue_mutex);
    int next_tail = (queue_tail + 1) % PACKET_BUFFER_SIZE;
    if (next_tail != queue_head) {
        packet_queue[queue_tail].pkthdr = pkthdr;
        packet_queue[queue_tail].packet = packet;
        queue_tail = next_tail;
        pthread_cond_signal(&queue_cond);
    }
    pthread_mutex_unlock(&queue_mutex);
}

// Process batch of packets
static void process_batch(struct pcap_pkthdr **pkthdr, const u_char **packet, char **source_ip, int count) {
    pthread_mutex_lock(&connection_mutex);
    
    for (int i = 0; i < count; i++) {
        struct ip *ip_header = (struct ip *)(packet[i] + 14);
        ConnectionTracker *conn = find_or_create_connection(source_ip[i]);
        
        if (conn) {
            update_connection_stats(conn, pkthdr[i], ip_header);
            check_attacks(conn, source_ip[i]);
        }
    }
    
    pthread_mutex_unlock(&connection_mutex);
}

// Find or create connection tracker
static ConnectionTracker* find_or_create_connection(const char *source_ip) {
    for (int i = 0; i < connection_count; i++) {
        if (strcmp(connections[i].source_ip, source_ip) == 0) {
            return &connections[i];
        }
    }
    
    if (connection_count < MAX_CONNECTIONS) {
        ConnectionTracker *conn = &connections[connection_count++];
        strncpy(conn->source_ip, source_ip, INET_ADDRSTRLEN);
        return conn;
    }
    
    return NULL;
}

// Update connection statistics
static void update_connection_stats(ConnectionTracker *conn, const struct pcap_pkthdr *pkthdr, struct ip *ip_header) {
    conn->packet_count++;
    conn->last_seen = time(NULL);
    
    // Update packet size statistics
    conn->packet_size_total += pkthdr->len;
    conn->packet_size_avg = conn->packet_size_total / conn->packet_count;
    if (pkthdr->len > conn->packet_size_max) {
        conn->packet_size_max = pkthdr->len;
    }
    if (pkthdr->len < conn->packet_size_min || conn->packet_size_min == 0) {
        conn->packet_size_min = pkthdr->len;
    }
    
    // Update protocol-specific statistics
    if (ip_header->ip_p == IPPROTO_TCP) {
        update_tcp_stats(conn, pkthdr, ip_header);
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        update_udp_stats(conn, pkthdr, ip_header);
    } else if (ip_header->ip_p == IPPROTO_ICMP) {
        update_icmp_stats(conn, pkthdr, ip_header);
    }
}

// Cleanup function
void cleanup() {
    worker_running = false;
    pthread_cond_broadcast(&queue_cond);
    
    for (int i = 0; i < MAX_THREADS; i++) {
        pthread_join(worker_threads[i], NULL);
    }
    
    pthread_mutex_destroy(&connection_mutex);
    pthread_mutex_destroy(&blocked_mutex);
    pthread_mutex_destroy(&log_mutex);
    pthread_mutex_destroy(&queue_mutex);
    pthread_cond_destroy(&queue_cond);
    
    if (connection_pool) {
        free(connection_pool);
    }
    
    if (log_file) {
        fclose(log_file);
    }
    
    save_protection_state();
}

// Initialize protection system
void init_protection() {
    init_connection_pool();
    init_worker_threads();
    load_protection_state();
    
    log_file = fopen("protection.log", "a");
    if (!log_file) {
        perror("Failed to open log file");
        exit(1);
    }
    
    is_monitoring = true;
    log_event("INFO", "SYSTEM", "Protection system initialized");
}

// ... (diğer fonksiyonlar aynı kalıyor) ... 