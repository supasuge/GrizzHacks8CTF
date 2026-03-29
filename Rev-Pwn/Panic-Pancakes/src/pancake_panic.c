/*
 * PANCAKE PANIC — Introductory pwnable challenge
 *
 * This deliberately vulnerable 64‑bit Linux program allocates a fixed
 * 64‑byte stack buffer and then reads up to 256 bytes into it. By
 * overflowing past the end of the buffer an attacker can clobber the
 * saved return address and redirect control flow into the hidden
 * flag‑printing function, `serve_flag()`. The binary also prints the
 * stack address of the buffer on startup to make the memory layout more
 * concrete for first‑time exploit developers.
 *
 * Build flags (see Makefile):
 *   -fno-stack-protector  disable stack canaries
 *   -z execstack          mark the stack executable (NX off)
 *   -no-pie               produce a position‑independent executable
 *   -O0                   no compiler optimisations
 *   -m64                  target the 64‑bit ABI
 *   -fcf-protection=none  disable CET/IBT instrumentation
 *   -w                    suppress warnings from the intentional overflow
 *   -s                    optional flag used in release builds to strip symbols
 *
 * Note: This program is intentionally unsafe and should only be run in
 *       controlled CTF or lab environments.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void print_banner(void)
{
    puts("");
    puts("   ____  _    _  _  ___  __   _  _  ____     ____   __   _  _  ____  ___  ");
    puts("  (  _ \\( \\/\\/ )( \\/ __)/ _\\ ( \\/ )(  __)   (  _ \\ / _\\ ( \\/ )( ___)(__ \\ ");
    puts("   ) __/ \\    /  ) ( (__/    \\ )  (  ) _)    ) __//    \\ )  (  )__)   / _/ ");
    puts("  (__)    \\//\\/  (_)\\___\\_/\\_/(_/\\_)(____)   (__)  \\_/\\_/(_/\\_)(____)  (__) ");
    puts("");
    puts("            ~~~ Chef Reginald's Haunted Diner ~~~");
    puts("          \"The Stack Is PERFECTLY Safe,\" he insists.");
    puts("");
    puts("    [*] A tower of 64 golden pancakes stands before you.");
    puts("    [*] Chef Reginald adjusts his toque nervously.");
    puts("");
}

static void print_menu(void)
{
    puts("    +-----------------------------------------------+");
    puts("    |         THE PANCAKE ORDER TERMINAL            |");
    puts("    |   Chef guarantees no more than 64 pancakes    |");
    puts("    |   can fit on one plate. Definitely. For sure. |");
    puts("    +-----------------------------------------------+");
    puts("");
}

/*
 * Hidden flag printer. Because it is marked static it will not be
 * referenced by any legitimate call sites, but an exploit may jump
 * directly to this function by overwriting the saved return address in
 * take_order(). It reads the flag from "flag.txt", prints it, flushes
 * stdout and then terminates the process via _exit(). Using _exit()
 * avoids any reliance on the corrupted call stack.
 */
static void serve_flag(void)
{
    FILE *fp;
    char flag[128];

    fp = fopen("flag.txt", "r");
    if (fp == NULL) {
        puts("\n    [Chef] The secret recipe vault is locked.");
        _exit(1);
    }

    if (fgets(flag, sizeof(flag), fp) == NULL) {
        puts("\n    [Chef] The recipe card is blank.");
        fclose(fp);
        _exit(1);
    }

    fclose(fp);

    puts("\n    [Chef] Reginald drops the forbidden menu behind the counter:");
    printf("    %s\n", flag);
    fflush(stdout);
    _exit(0);
}

/*
 * Vulnerable order routine. It allocates a 64‑byte stack buffer and
 * prints its address to the user. It then reads up to 256 bytes of
 * unvalidated input into that buffer. Because the return address is
 * located 72 bytes above the start of the buffer (64 bytes for the
 * buffer plus 8 bytes for the saved frame pointer), sending more
 * than 72 bytes will overwrite the saved RIP. A crafted payload can
 * therefore redirect execution directly into serve_flag().
 */
static void take_order(void)
{
    char buf[64];

    /* Leak the address of the buffer. This makes it easier to reason
     * about the stack layout when learning exploitation, but is not
     * strictly needed for the simple ret2win attack.
     */
    printf("    [Chef] Your plate is ready at address : %p\n", (void *)buf);
    printf("    [Chef] It can hold EXACTLY 64 pancakes. Trust me.\n\n");
    printf("    [>] How many pancakes would you like? ");
    fflush(stdout);

    /* Unsafely read up to 256 bytes. This is the core vulnerability. */
    read(STDIN_FILENO, buf, 256);

    puts("\n    [Chef] Reginald stares at the plate, visibly sweating.");
    puts("    [Chef] 'That is... a normal amount of pancakes,' he lies.\n");
}

int main(void)
{
    /* Unbuffer stdio so that printed prompts appear immediately when run
     * via a network socket. Without this, the initial leak and prompt
     * might remain buffered until process termination, confusing remote
     * exploit scripts.
     */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);

    print_banner();
    print_menu();
    take_order();

    /* If the attacker doesn't overflow the buffer then execution will
     * resume here, printing a benign message.
     */
    puts("    [Chef] 'Order complete!' Reginald mops his brow.");
    puts("    [Chef] 'Nothing unusual happened here. Good day.'\n");

    return 0;
}
