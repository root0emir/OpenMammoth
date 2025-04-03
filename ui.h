#ifndef UI_H
#define UI_H

void show_welcome_screen();
void show_main_menu();
void clear_screen();
void print_centered(const char *text);
void print_box(const char *title, const char *content);
void handle_menu_choice(int choice);

#endif 