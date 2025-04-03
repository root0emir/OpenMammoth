#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "network_protection.h"

// ANSI color codes
#define RED     "\x1b[31m"
#define GREEN   "\x1b[32m"
#define YELLOW  "\x1b[33m"
#define BLUE    "\x1b[34m"
#define MAGENTA "\x1b[35m"
#define CYAN    "\x1b[36m"
#define RESET   "\x1b[0m"

// ASCII art
const char *ascii_art = RED
"                                #**********                                \n"
"                             ##%=-=+#########*                            \n"
"                            *%==##############*                           \n"
"                           *#==################*                          \n"
"                       +**###-**###################**                     \n"
"                     +=######-=*#####################*                    \n"
"                    +=######+-*#######################*                   \n"
"                    +######*-*#########################                   \n"
"                    *#*####+-**-###########==##*####+#*                   \n"
"                    ##+#####==####+:-=-:*#####*#####*#*                   \n"
"                       *#####==##-##################*                     \n"
"                       #######-#+=*----=*########*#*                      \n"
"                 *##*   ##*##*-#==###########*###*#  *###*               \n"
"              **%%*       *##+=#==#+=-=*####*=##*       *##*             \n"
"             *###          **#=#=-*#####*#####**          *##*            \n"
"            *##*             ###+-##***#######*            *##*           \n"
"           *###             **-**-=*###**#####*#            ###*          \n"
"           *###            ##-*##-*############*#           ####          \n"
"           *####         *#+-####--+*##+*##*#####*          ####          \n"
"           *###**      *#*-=##*#*==#########*######*      **###*          \n"
"            *#####***##+-=###*  **--=+++##*  *########***#####**          \n"
"             *###+---=+####*    *#-#######*    *#############*            \n"
"               **#######*#      #%-===+###*      **#######**              \n"
"                                 #++######                                \n"
"                                 **-#*####                                \n"
"                             ##%#*#:+####*                                \n"
"                            *##* **-#####                                 \n"
"                           ***##*%=#####*                                 \n"
"                            *#**-=#####*                                  \n"
"                             **######+                                    \n"
"                                ***                                       \n" RESET;

void display_help() {
    printf("\n%sOpenMammoth Network Protection Toolkit%s\n", RED, RESET);
    printf("%s==========================================%s\n\n", RED, RESET);
    printf("Usage: openmammoth [OPTIONS]\n\n");
    printf("Options:\n");
    printf("  %s-h, --help%s           Display this help menu\n", GREEN, RESET);
    printf("  %s-i, --interface%s      Specify network interface (default: eth0)\n", GREEN, RESET);
    printf("  %s-l, --level%s          Protection level (1-4)\n", GREEN, RESET);
    printf("  %s-a, --advanced%s       Advanced protection (0/1)\n", GREEN, RESET);
    printf("  %s-d, --debug%s          Debug mode\n", GREEN, RESET);
    printf("  %s-c, --config%s         Configuration file\n", GREEN, RESET);
    printf("  %s-r, --rules%s          Custom rules file\n", GREEN, RESET);
    printf("  %s-s, --stats%s          Show statistics\n", GREEN, RESET);
    printf("  %s-b, --blocked%s        Show blocked IPs\n", GREEN, RESET);
    printf("  %s-v, --version%s        Show version information\n\n", GREEN, RESET);
    
    printf("Protection Levels:\n");
    printf("  %s1%s - Low: Basic protection\n", YELLOW, RESET);
    printf("  %s2%s - Medium: Standard protection\n", YELLOW, RESET);
    printf("  %s3%s - High: Enhanced protection\n", YELLOW, RESET);
    printf("  %s4%s - Extreme: Maximum protection\n\n", YELLOW, RESET);
    
    printf("Example Usage:\n");
    printf("  %sopenmammoth -i eth0 -l 3 -a 1%s\n", CYAN, RESET);
    printf("  %sopenmammoth --interface wlan0 --level 4 --advanced 1%s\n", CYAN, RESET);
    printf("  %sopenmammoth -c config.json -r rules.txt%s\n", CYAN, RESET);
    printf("  %sopenmammoth -s -b%s\n\n", CYAN, RESET);
    
    printf("Note: Root privileges required.\n");
}

void display_version() {
    printf("\n%sOpenMammoth Network Protection Toolkit%s\n", RED, RESET);
    printf("%s==========================================%s\n\n", RED, RESET);
    printf("Version: 1.0.0\n");
    printf("License: GPL v3\n");
    printf("Author: root0emir\n");
    printf("Github: https://github.com/root0emir\n\n");
}

void display_welcome_screen() {
    printf("%s\n", ascii_art);
    printf("%sOpenMammoth Network Protection Toolkit%s\n", RED, RESET);
    printf("%s==========================================%s\n\n", RED, RESET);
    printf("Starting Protection System...\n\n");
}

void display_protection_stats() {
    printf("\n%sProtection Statistics%s\n", RED, RESET);
    printf("%s=====================%s\n\n", RED, RESET);
    
    printf("Total Packets: %d\n", get_total_packets());
    printf("Blocked IPs: %d\n", get_blocked_ips_count());
    printf("Active Connections: %d\n", get_active_connections());
    printf("Detected Attacks: %d\n", get_detected_attacks());
    printf("Protection Level: %d\n", get_protection_level());
    printf("Advanced Protection: %s\n", is_advanced_protection_enabled() ? "Enabled" : "Disabled");
    printf("\n");
}

void display_blocked_ips() {
    printf("\n%sBlocked IPs%s\n", RED, RESET);
    printf("%s===============%s\n\n", RED, RESET);
    
    BlockedIP *ips = get_blocked_ips();
    int count = get_blocked_ips_count();
    
    if (count == 0) {
        printf("No blocked IPs found.\n\n");
        return;
    }
    
    printf("%-15s %-20s %-10s %-30s\n", "IP", "Block Time", "Level", "Reason");
    printf("------------------------------------------------------------------------\n");
    
    for (int i = 0; i < count; i++) {
        char time_str[20];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&ips[i].blocked_at));
        printf("%-15s %-20s %-10d %-30s\n", 
               ips[i].ip, 
               time_str, 
               ips[i].threat_level, 
               ips[i].reason);
    }
    printf("\n");
}

void display_error(const char *message) {
    fprintf(stderr, "%sError: %s%s\n", RED, message, RESET);
}

void display_warning(const char *message) {
    fprintf(stderr, "%sWarning: %s%s\n", YELLOW, message, RESET);
}

void display_success(const char *message) {
    printf("%sSuccess: %s%s\n", GREEN, message, RESET);
}

void display_info(const char *message) {
    printf("%sInfo: %s%s\n", BLUE, message, RESET);
}

void display_debug(const char *message) {
    printf("%sDebug: %s%s\n", MAGENTA, message, RESET);
} 