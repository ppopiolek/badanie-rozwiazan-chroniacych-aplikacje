#include <stdio.h>
#include <stdlib.h>

void get_users_name()
{
    char name[64] = {0};
    puts("Podaj imie:");
    gets(name);
    printf("Czesc %s!\n", name);
}

int main()
{
    int x;
    printf("Adres na stosie main: %p\n", &x);
    get_users_name();
    return 0;
}



