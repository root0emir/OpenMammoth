#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include "network_protection.h"
#include "ui.h"

#define MAX_PACKET_SIZE 65536

// ANSI renk kodları
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define BLUE    "\x1b[34m"
#define MAGENTA "\x1b[35m"
#define CYAN    "\x1b[36m"
#define RESET   "\x1b[0m"

// ASCII art
const char *ascii_art = RED
"  ___  ____  __  __  __  __  ___  _  _  ___  __  __  ___  _  _  _  _ \n"
" / _ \\|  _ \\|  \\/  |/  \\|  \\/  |/ _ \\| \\| |/ _ \\|  \\/  |/ _ \\| \\| |/ \\| |\n"
"| |_| | |_) | |\\/| | /\\ | |\\/| | |_| | .` | (_) | |\\/| | |_| | .` | o | |\n"
" \\___/|  __/|_|  |_|_||_|_|  |_|\\___/|_|\\_|\\___/|_|  |_|\\___/|_|\\_|\\_/|_|\n"
"      |_|                                                                  \n" RESET;

// Global variables
pcap_t *handle = NULL;
char *interface = "eth0";
int protection_level = 2;
int advanced_protection = 0;
int debug_mode = 0;
char *config_file = NULL;
char *rules_file = NULL;

// Signal handler
void signal_handler(int signum) {
    if (signum == SIGINT || signum == SIGTERM) {
        display_info("Shutting down...");
        if (handle) {
            pcap_breakloop(handle);
        }
    }
}

// Packet handler
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    analyze_packet(packet, pkthdr->len);
}

// Initialize packet capture
int init_packet_capture() {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Open interface
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        display_error(errbuf);
        return -1;
    }
    
    // Set filter
    struct bpf_program fp;
    char filter_exp[] = "ip";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        display_error("Couldn't parse filter");
        return -1;
    }
    
    if (pcap_setfilter(handle, &fp) == -1) {
        display_error("Couldn't install filter");
        return -1;
    }
    
    return 0;
}

// Cleanup function
void cleanup() {
    if (handle) {
        pcap_close(handle);
    }
    cleanup_protection();
}

int main(int argc, char *argv[]) {
    // Command line options
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"interface", required_argument, 0, 'i'},
        {"level", required_argument, 0, 'l'},
        {"advanced", required_argument, 0, 'a'},
        {"debug", no_argument, 0, 'd'},
        {"config", required_argument, 0, 'c'},
        {"rules", required_argument, 0, 'r'},
        {"stats", no_argument, 0, 's'},
        {"blocked", no_argument, 0, 'b'},
        {"version", no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "hi:l:a:dc:r:sbv", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                display_help();
                return 0;
            case 'i':
                interface = optarg;
                break;
            case 'l':
                protection_level = atoi(optarg);
                if (protection_level < 1 || protection_level > 4) {
                    display_error("Invalid protection level");
                    return 1;
                }
                break;
            case 'a':
                advanced_protection = atoi(optarg);
                break;
            case 'd':
                debug_mode = 1;
                break;
            case 'c':
                config_file = optarg;
                break;
            case 'r':
                rules_file = optarg;
                break;
            case 's':
                display_protection_stats();
                return 0;
            case 'b':
                display_blocked_ips();
                return 0;
            case 'v':
                display_version();
                return 0;
            default:
                display_help();
                return 1;
        }
    }
    
    // Check root privileges
    if (geteuid() != 0) {
        display_error("This program requires root privileges");
        return 1;
    }
    
    // Set signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize protection
    if (init_protection(protection_level, advanced_protection, debug_mode) != 0) {
        display_error("Failed to initialize protection");
        return 1;
    }
    
    // Load configuration if specified
    if (config_file) {
        if (load_config(config_file) != 0) {
            display_error("Failed to load configuration");
            return 1;
        }
    }
    
    // Load custom rules if specified
    if (rules_file) {
        if (load_custom_rules(rules_file) != 0) {
            display_error("Failed to load custom rules");
            return 1;
        }
    }
    
    // Initialize packet capture
    if (init_packet_capture() != 0) {
        display_error("Failed to initialize packet capture");
        return 1;
    }
    
    // Show welcome screen
    display_welcome_screen();
    
    // Start packet capture
    display_info("Starting packet capture...");
    pcap_loop(handle, -1, packet_handler, NULL);
    
    // Cleanup
    cleanup();
    return 0;
} 