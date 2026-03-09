# Semantic Shellcode Injection — Exécuter des syscalls arbitraires en C pur

**Auteur :** Étudiant à l'école 42 Lyon Auvergne Rhône Alpes, 1 an d'expérience en C 
**Niveau :** Avancé — x86-64, ABI System V, compilation C, ROP  
**Tags :** `low-level` `exploitation` `shellcode` `C` `x86-64` `syscall` `ROP` `compiler-behavior`

---

## Introduction

Ce write-up documente une technique originale d'exécution de syscalls arbitraires en C pur, sans appel à `mmap`, `mprotect`, ou toute autre allocation explicite de mémoire exécutable. La technique repose sur une propriété fondamentale et inévitable de la compilation :

> **Toute valeur immédiate utilisée dans une expression C est encodée en clair dans le segment `.text`, qui est par nature exécutable.**

En choisissant soigneusement ces valeurs immédiates, il est possible d'y faire apparaître du shellcode fonctionnel — non pas en écrivant des octets manuellement, mais en contraignant le compilateur à les produire lui-même via la sémantique ordinaire du langage.

Trois versions progressives sont présentées :

- **V1** : Exécution par détournement de stack frame, uniquement par assignations de variables locales.
- **V2** : Exécution par scan dynamique du `.text`, robuste face à toutes les optimisations du compilateur.
- **V3** : Extension à des syscalls complexes (6 arguments, registre `r10`) via une chaîne de gadgets ROP générés par immédiats et orchestrée depuis la stack.

---

## Prérequis

- Architecture x86-64, Linux
- ABI System V AMD64 — arguments passés dans `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`
- Convention syscall Linux x86-64 — arguments dans `rax`, `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`
- Connaissance de base du prologue/épilogue de fonction en assembleur
- Notion de Return-Oriented Programming (ROP)

---

## Contexte : la divergence ABI / syscall

Un détail fondamental motive la complexité de la V3 :

| Position | ABI System V | Syscall Linux |
|---|---|---|
| arg 4 | `rcx` | `r10` |

Le registre `r10` n'est jamais chargé par l'ABI. Pour tout syscall utilisant un 4ème argument (`mmap`, `openat`, etc.), le shellcode doit explicitement charger `r10` — ce que la libc fait en interne mais que l'ABI ne fait pas.

---

## V1 — Shellcode par assignations pures

### Code

```c
void    function(int fd, char *str, unsigned long len)
{
    unsigned long    buffer[2];

    buffer[1] = 0x0007ebe589485552;
    buffer[1] = 0x06ebdc7d8b58016a;
    buffer[1] = 0x000008ebd0758b48;
    buffer[1] = 0xc3c9050fc8558b48;
    buffer[0] = buffer[5];
    buffer[5] = (unsigned long)function + 40;
    buffer[0] = buffer[0] + buffer[1];
}
```

### Injection par valeur immédiate

Chaque assignation à `buffer[1]` force le compilateur à encoder la constante dans le `.text`. Les quatre valeurs, décodées en little-endian, forment un shellcode `write` complet :

```asm
; 0x0007ebe589485552
push rdx          ; sauvegarde len
push rbp
mov  rbp, rsp
jmp  +7           ; saute les octets nuls de padding

; 0x06ebdc7d8b58016a
push 0x1          ; SYS_write = 1
pop  rax
mov  edi, [rbp-0x24]   ; fd depuis la stack frame de l'appelant
jmp  +6

; 0x000008ebd0758b48
mov  rsi, [rbp-0x30]   ; str depuis la stack frame
jmp  +8

; 0xc3c9050fc8558b48
mov  rdx, [rbp-0x38]   ; len depuis la stack frame
syscall
leave
ret
```

Les `jmp` courts sautent les octets nuls introduits par l'encodage 64 bits — le shellcode est continu malgré le padding.

### Détournement de la return address

```c
buffer[0] = buffer[5];               // sauvegarde la vraie return address
buffer[5] = (unsigned long)function + 40; // écrase la return address → shellcode
```

`buffer[5]` correspond à la return address sur la stack. Au `ret`, l'exécution saute directement au shellcode injecté.

### Transport de la return address via `rdx`

```c
buffer[0] = buffer[0] + buffer[1];
```

Pour effectuer l'addition, le compilateur charge `buffer[1]` dans `rdx` :

```asm
mov rax, [rbp-16]
mov rdx, [rbp-8]    ; rdx = vraie return address sauvegardée
add rax, rdx
mov [rbp-16], rax
```

`rdx` survit jusqu'au `ret` sans être écrasé. Le shellcode le lit pour reprendre l'exécution normale après le syscall — sans aucune variable explicite, uniquement grâce à la persistance d'un registre intermédiaire d'une opération arithmétique.

### Limites

- Offset `buffer[5]` dépendant du layout de stack généré par le compilateur.
- Offset `function + 40` dépendant de l'emplacement exact des immédiats dans le `.text`.
- Ces deux valeurs varient avec les flags de compilation et la version du compilateur.

---

## V2 — Scan dynamique, robustesse totale

### Code

```c
long    write(int fd, char *buf, unsigned long len)
{
    unsigned long    ptr;
    long             result;

    ptr = (unsigned long)write;
    while (*(unsigned long *)ptr != 0xc3050f58016a)
        ptr++;
    result = ((long (*)(int, void *, unsigned long))ptr)(fd, buf, len);
    return (result);
}
```

### Le principe

La condition du `while` compare une valeur lue en mémoire à la constante `0xc3050f58016a`. Pour effectuer cette comparaison, le compilateur génère :

```asm
mov rax, 0x0000c3050f58016a
cmp [ptr], rax
```

La constante est encodée dans le `.text` sous la forme (little-endian) :

```
6a 01   →  push 0x1      ; SYS_write = 1
58      →  pop rax
0f 05   →  syscall
c3      →  ret
```

**La constante de comparaison est un shellcode `write` complet.** Le compilateur l'a écrit dans une zone exécutable uniquement parce que la sémantique de la comparaison l'y contraint.

Le scan localise cette séquence depuis le début de la fonction, puis l'appelle directement. L'ABI place `fd` dans `rdi`, `buf` dans `rsi`, `len` dans `rdx` — exactement ce qu'attend le syscall.

### Robustesse

Cette version ne dépend d'aucun offset, d'aucun layout de stack frame. Le compilateur doit matérialiser la constante dans le `.text` quelle que soit l'optimisation — ce comportement est **invariant** sous `-O0`, `-O3`, `-fomit-frame-pointer` ou toute autre combinaison de flags.

---

## V3 — Chaîne de gadgets ROP pour syscalls complexes

### Motivation

`mmap` requiert 6 arguments dont le 4ème doit aller dans `r10` — registre absent de l'ABI. Une séquence immédiate unique ne suffit plus : il faut une **chaîne de gadgets** qui setup les registres progressivement, en utilisant la stack comme mémoire intermédiaire.

### Architecture générale

```
Code C                    Stack                    Gadgets
─────────────────         ──────────────────       ──────────────────
setup1(args)         →    empile addr, len,    →   gadget1
setup2(args)         →    empile prot, flags,  →     └─ call → gadget2
gadget1(g2, g3, g4)  →    empile fd, offset,       gadget2
                          empile SYS_mmap              └─ call → gadget3
                                                    gadget3
                                                       └─ call → gadget4
                                                    gadget4
                                                    → retour chaîne
                                                    → syscall dans gadget1
```

### Code complet

```c
#include <stdio.h>

void	*mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
	size_t	result;
	size_t	gadget1;
	size_t	gadget2;
	size_t	gadget3;
	size_t	gadget4;
	size_t	setup;

	// Setup1 : empile SYS_mmap + addr + length + prot
	setup = (size_t)mmap;
	while (*(size_t *)setup != 0xC353525657096A5B)
		setup++;
	((void (*)(void *, size_t, int, int, int, off_t))setup)(addr, length, prot, flags, fd, offset);

	// Setup2 : empile flags + fd + offset
	setup = (size_t)mmap;
	while (*(size_t *)setup != 0xC35351415041515B)
		setup++;
	((void (*)(void *, size_t, int, int, int, off_t))setup)(addr, length, prot, flags, fd, offset);

	// Localisation des gadgets ROP
	gadget1 = (size_t)mmap;
	gadget2 = (size_t)mmap;
	gadget3 = (size_t)mmap;
	gadget4 = (size_t)mmap;
	while (*(size_t *)gadget1 != 0xC353050F58D7FF5B)
		gadget1++;
	while (*(size_t *)gadget2 != 0xC3505F5E5AD6FF58)
		gadget2++;
	while (*(size_t *)gadget3 != 0xC3575A41D2FF5F)
		gadget3++;
	while (*(size_t *)gadget4 != 0xC356584159415E)
		gadget4++;

	// Lancement de la chaîne — gadget2/3/4 passés via ABI dans rdi/rsi/rdx
	result = ((size_t (*)(size_t, size_t, size_t))gadget1)(gadget2, gadget3, gadget4);
	return ((void *)result);
}
```

### Décodage des gadgets

**Setup1** — `0xC353525657096A5B`
```asm
pop  rbx        ; sauvegarde continuation
push 0x9        ; SYS_mmap = 9
push rdi        ; addr
push rsi        ; length
push rdx        ; prot
push rbx        ; restaure continuation
ret
```

**Setup2** — `0xC35351415041515B`
```asm
pop  rbx        ; sauvegarde continuation
push rcx        ; flags
push r8         ; fd  (REX prefix — 2 bytes)
push r9         ; offset
push rbx        ; restaure continuation
ret
```

**Gadget1** — `0xC353050F58D7FF5B` — point d'entrée + syscall
```asm
pop  rbx        ; sauvegarde continuation
call rdi        ; → gadget2  (rdi reçu par ABI)
pop  rax        ; SYS_mmap = 9 depuis la stack
syscall
push rbx
ret
```

**Gadget2** — `0xC3505F5E5AD6FF58` — charge rdi, rsi, rdx
```asm
pop  rax        ; sauvegarde continuation
call rsi        ; → gadget3  (rsi reçu par ABI)
pop  rdx        ; prot
pop  rsi        ; length
pop  rdi        ; addr
push rax        ; restaure continuation
ret
```

**Gadget3** — `0xC3575A41D2FF5F` — charge r10 (flags)
```asm
pop  rdi        ; sauvegarde continuation
call rdx        ; → gadget4  (rdx reçu par ABI)
pop  r10        ; flags  (REX prefix — 2 bytes)
push rdi        ; restaure continuation
ret
```

**Gadget4** — `0xC356584159415E` — charge r8, r9, rcx
```asm
pop  r14        ; sauvegarde continuation  (REX — 2 bytes)
pop  rcx        ; fd
pop  r9         ; offset  (REX — 2 bytes)
pop  rsi        ; (padding alignement)
push r14        ; restaure continuation
ret
```

### Schéma de la chaîne d'exécution

```
gadget1(gadget2, gadget3, gadget4)
   │  rdi=gadget2, rsi=gadget3, rdx=gadget4
   │
   ├─ pop rbx          (sauvegarde retour vers appelant C)
   ├─ call rdi ────────────────────────────────────────┐
   │                                                   ▼
   │                                              gadget2
   │                                          pop rax  (sauvegarde retour vers gadget1)
   │                                          call rsi ──────────────────────────────┐
   │                                                                                 ▼
   │                                                                            gadget3
   │                                                                        pop rdi  (sauvegarde retour vers gadget2)
   │                                                                        call rdx ──────────────────┐
   │                                                                                                   ▼
   │                                                                                              gadget4
   │                                                                                          pop r14
   │                                                                                          pop rcx   fd
   │                                                                                          pop r9    offset
   │                                                                                          push r14
   │                                                                                          ret ──────┘
   │                                                                        pop r10   flags
   │                                                                        push rdi
   │                                                                        ret ───────────────────────┘
   │                                          pop rdx   prot
   │                                          pop rsi   length
   │                                          pop rdi   addr
   │                                          push rax
   │                                          ret ───────────────────────────────────┘
   ├─ pop rax          SYS_mmap = 9
   ├─ syscall          rax=9, rdi=addr, rsi=length, rdx=prot, r10=flags, r8=fd, r9=offset
   ├─ push rbx
   └─ ret              → retour au code C appelant
```

### Propriétés de la chaîne

Chaque gadget suit la structure :

```asm
pop  reg_save    ; 1 byte  — sauvegarde la continuation avant que call la pollue
call reg_next    ; 2 bytes — saute au gadget suivant
[action]         ; 3 bytes max — pops vers registres syscall
push reg_save    ; 1 byte  — restaure la continuation
ret              ; 1 byte  — reprend le fil de retour
```

**Budget par gadget : 8 bytes.** Les registres étendus (`r8`-`r15`) coûtent 2 bytes (préfixe REX), ce qui contraint les gadgets qui en ont besoin à réduire leur action à 1 byte restant.

La stack joue le rôle de **file de registres étendue** : les valeurs des arguments sont déposées par les setups, consommées dans l'ordre par les gadgets via `pop`, sans qu'aucun registre ne soit partagé entre gadgets pour transporter des données.

---

## Comparaison des trois versions

| Critère | V1 | V2 | V3 |
|---|---|---|---|
| Dépendance au layout de stack | Oui | Non | Non |
| Dépendance aux offsets de compilation | Oui | Non | Non |
| Robustesse `-O3` / `-fomit-frame-pointer` | Non | Oui | Oui |
| Syscalls supportés | 3 args max (ABI) | 3 args max (ABI) | 6 args + r10 |
| Pureté de la contrainte | Maximum | Élevée | Élevée |
| Extensibilité | Faible | Moyenne | Illimitée |

---

## Relation avec les techniques existantes

**Return-Oriented Programming (ROP)** — le ROP classique *cherche* des gadgets dans un binaire existant. Ici, les gadgets sont *générés volontairement* par le compilateur via des constantes littérales choisies pour leur encodage binaire.

**Data-Only Attacks** — modification de données sans injection de code. Ici, le code existe déjà dans le `.text`, matérialisé passivement par le compilateur.

**Compiler-assisted exploitation** — exploitation du comportement déterministe du compilateur. La surface d'attaque n'est pas une vulnérabilité mémoire mais la sémantique obligatoire du langage C.

La distinction principale avec toutes ces techniques : **aucun octet de code n'est écrit manuellement en mémoire, aucune protection mémoire n'est contournée.** Le shellcode et les gadgets émergent comme effets de bord inévitables de la compilation d'expressions C syntaxiquement légitimes.

---

## Conclusion

Ces trois techniques forment une progression cohérente autour d'un principe unique : **le compilateur, contraint par la sémantique du langage, produit exactement les octets souhaités dans des zones exécutables, sans en avoir conscience.**

La V3 démontre que cette approche est extensible à des syscalls arbitrairement complexes. En combinant la génération d'immédiats, le scan dynamique, et une chaîne de gadgets orchestrée depuis la stack, il est possible d'exécuter n'importe quel syscall Linux x86-64 depuis du code C pur — sans mémoire exécutable allouée, sans écriture manuelle d'octets, sans contournement de protections.

Le vecteur est le compilateur lui-même. La technique s'appelle **Semantic Shellcode Injection**.

---

*Ce travail a été réalisé dans un cadre purement éducatif et de recherche personnelle.*
