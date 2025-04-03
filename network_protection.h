#ifndef NETWORK_PROTECTION_H
#define NETWORK_PROTECTION_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pthread.h>

// Performance constants
#define MAX_CONNECTIONS 100000
#define MAX_BLOCKED_IPS 10000
#define MAX_CUSTOM_RULES 1000
#define CONNECTION_TIMEOUT 300
#define BLOCK_DURATION 3600
#define CLEANUP_INTERVAL 60
#define MAX_PACKET_SIZE 65535
#define PACKET_BUFFER_SIZE 1024
#define MAX_THREADS 4
#define BATCH_SIZE 100

// Protection thresholds
#define PORT_SCAN_THRESHOLD 100
#define SYN_FLOOD_THRESHOLD 1000
#define UDP_FLOOD_THRESHOLD 1000
#define ICMP_FLOOD_THRESHOLD 1000
#define FRAGMENT_ATTACK_THRESHOLD 100
#define MALFORMED_PACKET_THRESHOLD 100
#define RATE_LIMIT_THRESHOLD 1000
#define THREAT_SCORE_THRESHOLD 50

// Attack types
typedef enum {
    ATTACK_NONE = 0,
    ATTACK_PORT_SCAN,
    ATTACK_SYN_FLOOD,
    ATTACK_UDP_FLOOD,
    ATTACK_ICMP_FLOOD,
    ATTACK_FRAGMENT,
    ATTACK_MALFORMED,
    ATTACK_RATE_LIMIT,
    ATTACK_GEO_BLOCK,
    ATTACK_VPN_TOR,
    ATTACK_BOTNET,
    ATTACK_MALWARE,
    ATTACK_EXPLOIT,
    ATTACK_ZERO_DAY,
    ATTACK_CUSTOM
} AttackType;

// Connection tracker structure
typedef struct {
    char ip[INET_ADDRSTRLEN];
    int packet_count;
    int syn_count;
    int udp_count;
    int icmp_count;
    int fragment_count;
    int malformed_packets;
    int rate_limit_count;
    char geo_location[3];
    char country_code[3];
    int is_vpn;
    int is_tor;
    int threat_score;
    time_t last_seen;
    time_t first_seen;
    AttackType attack_type;
} ConnectionTracker;

// Blocked IP structure
typedef struct {
    char ip[INET_ADDRSTRLEN];
    time_t blocked_at;
    time_t block_until;
    int threat_level;
    char reason[256];
    char country[3];
    int permanent_block;
    time_t first_blocked;
    int total_attacks;
} BlockedIP;

// Custom rule structure
typedef struct {
    char name[64];
    char pattern[256];
    int action;
    int priority;
    time_t created_at;
    time_t last_modified;
    char description[256];
} CustomRule;

// Global variables
extern ConnectionTracker *connections;
extern BlockedIP *blocked_ips;
extern CustomRule *custom_rules;
extern int connection_count;
extern int blocked_ip_count;
extern int custom_rule_count;
extern pthread_mutex_t connection_mutex;
extern pthread_mutex_t blocked_ip_mutex;
extern pthread_mutex_t custom_rule_mutex;
extern pthread_mutex_t log_mutex;

// Function declarations
int init_protection(int level, int advanced, int debug);
void cleanup_protection();
int analyze_packet(const u_char *packet, int length);
int block_ip(const char *ip, AttackType attack_type, int threat_level);
int unblock_ip(const char *ip);
int load_config(const char *filename);
int load_custom_rules(const char *filename);
int save_config(const char *filename);
int save_custom_rules(const char *filename);
int get_total_packets();
int get_blocked_ips_count();
int get_active_connections();
int get_detected_attacks();
int get_protection_level();
int is_advanced_protection_enabled();
BlockedIP *get_blocked_ips();

// Attack detection functions
int check_port_scan(ConnectionTracker *tracker);
int check_syn_flood(ConnectionTracker *tracker);
int check_udp_flood(ConnectionTracker *tracker);
int check_icmp_flood(ConnectionTracker *tracker);
int check_fragment_attack(ConnectionTracker *tracker);
int check_malformed_packets(ConnectionTracker *tracker);
int check_rate_limiting(ConnectionTracker *tracker);
int check_geo_location(ConnectionTracker *tracker);
int check_vpn_tor(ConnectionTracker *tracker);
int check_botnet_activity(ConnectionTracker *tracker);
int check_malware_signatures(ConnectionTracker *tracker);
int check_exploit_attempts(ConnectionTracker *tracker);
int check_zero_day_attacks(ConnectionTracker *tracker);
int check_custom_rules(ConnectionTracker *tracker);
int calculate_threat_score(ConnectionTracker *tracker);

#endif // NETWORK_PROTECTION_H 