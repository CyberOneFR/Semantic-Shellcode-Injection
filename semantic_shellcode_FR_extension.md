# Semantic Shellcode Injection — Extension
## Définition Formelle & Conditions d'Applicabilité

**Auteur :** Étudiant à l'école 42 Lyon Auvergne Rhône Alpes, 1 an d'expérience en C  
**Tags :** `SSI` `définition-formelle` `théorie-des-langages` `JIT` `interpréteur` `surface-d-attaque`

---

## Préface

Le write-up original documentait SSI comme une technique propre au C. Lors de l'extension de la recherche à JavaScript/V8 puis à Lua, une question plus profonde a émergé : SSI est-il spécifique au C, ou décrit-il une classe d'attaque plus générale ?

Cette extension répond à cette question en formalisant SSI et en dérivant les conditions sous lesquelles la technique s'applique — ou ne s'applique pas — à n'importe quel runtime.

---

## Définition Formelle

> **Semantic Shellcode Injection (SSI)** est une technique dans laquelle un attaquant choisit des constructions au niveau source — constantes, expressions, bornes de boucle, comparaisons — dont l'encodage binaire par le compilateur ou le JIT constitue du code exécutable valide (shellcode ou gadgets), forçant le runtime à placer ce code dans une région mémoire exécutable comme effet de bord inévitable de la sémantique normale du langage.

Trois propriétés distinguent SSI des techniques d'injection classiques :

**Propriété 1 — Légitimité sémantique**  
Le code source est syntaxiquement et sémantiquement valide dans le langage cible. Aucune écriture mémoire directe, aucun débordement de tampon, aucun buffer shellcode explicite. Le compilateur ou le JIT agit en pleine conformité avec la spécification du langage.

**Propriété 2 — Placement forcé par le compilateur**  
L'attaquant n'écrit pas d'octets en mémoire. C'est la chaîne de compilation qui les écrit, parce que le langage l'exige. Le placement est une conséquence nécessaire de la sémantique de compilation, et non l'effet de bord d'une vulnérabilité.

**Propriété 3 — Région exécutable**  
Les octets atterrissent dans une région que le CPU peut directement exécuter : le segment `.text` dans les langages compilés, ou la région de code JIT dans les langages JIT. Aucun `mprotect`, aucun `mmap`, aucun contournement de W^X requis.

---

## La Condition Nécessaire — La Frontière Source-vers-Exécutable

La recherche sur C, JavaScript/V8 et Lua a permis d'identifier une condition nécessaire unique à SSI. Nous l'appelons la **frontière source-vers-exécutable** :

> **SSI requiert qu'il existe un chemin depuis une construction au niveau source vers une séquence d'octets dans une région mémoire exécutable par le CPU, tel que la séquence d'octets soit déterminée par la valeur de la construction.**

Cette frontière existe sous deux formes :

### Frontière directe — langages compilés

```
Constante source  →  compilateur encode comme immédiat x86  →  atterrit dans .text
```

Le chemin est déterministe et inconditionnel. Toute affectation C de la forme `x = 0xdeadbeef` amène le compilateur à écrire ces octets dans `.text`. SSI est trivialement applicable.

Langages concernés : C, C++, Rust, Zig, Go, assembleur.

### Frontière indirecte — langages JIT

```
Constante source  →  compilateur JIT  →  code natif spéculatif  →  région JIT
```

Le chemin existe mais dépend des heuristiques du JIT : la fonction doit être suffisamment chaude pour être compilée, le feedback de type doit être suffisamment stable pour que le JIT se spécialise, et la constante doit survivre aux optimisations comme le constant folding ou le constant blinding.

La recherche sur V8/TurboFan a confirmé l'existence de cette frontière pour JavaScript :

```javascript
// Injection 4 octets via borne de boucle (cmpl imm32)
for (let i = 0; i < 0x1000bead; i++) { ... }
// TurboFan émet : 81 f9 ad be 00 10 dans la région JIT

// Injection 8 octets via store BigUint64Array
view[0] = 0xdeadbeefdeadbeefn;
// TurboFan émet : REX.W movq reg, 0xdeadbeefdeadbeef dans la région JIT
```

Langages concernés : JavaScript (V8, SpiderMonkey), LuaJIT, Java (JIT JVM), C# (.NET RyuJIT), PyPy.

### Aucune frontière — interpréteurs purs

```
Constante source  →  heap de l'interpréteur  →  ne devient jamais des instructions CPU
```

Dans un interpréteur pur, les constantes sont stockées comme des objets de données sur le heap de la VM. La VM les exécute via une boucle de dispatch `switch/case` en C — les constantes sont des opérandes, jamais des instructions. Aucun octet écrit depuis le code source n'atteint jamais une région exécutable.

Langages concernés : Lua (standard), CPython, Ruby MRI, la plupart des moteurs de scripting embarqués.

**SSI au sens x86 est impossible dans les interpréteurs purs.** Ce n'est pas une protection — c'est une conséquence architecturale du modèle d'interprétation.

---

## Classification des Langages

| Runtime | Type | Frontière | SSI applicable | Syscall direct |
|---|---|---|---|---|
| C / C++ / Rust / Zig | Compilé | Directe (.text) | ✓ trivial | ✓ |
| JavaScript / V8 | JIT (TurboFan) | Indirecte (région JIT) | ◑ injection oui, exécution bloquée | ✗ sandboxé |
| LuaJIT | JIT (trace-based) | Indirecte (région JIT) | ◑ probablement atteignable | ◑ selon contexte |
| Java / .NET | JIT (JVM / RyuJIT) | Indirecte (région JIT) | ◑ selon contexte | ◑ selon contexte |
| Lua (standard) | Interpréteur pur | Aucune | ✗ impossible | ✗ |
| CPython / Ruby MRI | Interpréteur pur | Aucune | ✗ impossible | ✗ |

---

## SSI-VM — La Variante Bytecode pour les Interpréteurs Purs

Même lorsque la frontière x86 directe est absente, un analogue plus faible s'applique aux langages qui exposent leur propre bytecode à l'exécution. Nous appelons cela **SSI-VM**.

> **SSI-VM** est une variante dans laquelle le payload injecté est constitué d'opcodes VM plutôt que d'instructions x86, exploitant le mécanisme de chargement de bytecode du langage lui-même comme vecteur d'exécution.

En Lua, cela est exposé nativement :

```lua
-- string.dump() sérialise une fonction en son bytecode brut
local bytecode = string.dump(function()
    local x = 0xdeadbeef  -- cette constante apparaît verbatim dans le bytecode
end)

-- Les octets du bytecode peuvent être modifiés directement
local patche = bytecode:sub(1, offset - 1) .. opcodes_payload .. bytecode:sub(offset + n)

-- load() compile et exécute du bytecode arbitraire
load(patche)()
```

Les capacités de SSI-VM sont bornées par ce que la VM elle-même permet. Si l'application hôte a supprimé `os`, `io` et `debug` de l'environnement (comme le font Roblox, CS2 et WoW), SSI-VM ne peut opérer que dans ces contraintes. Il n'existe aucun chemin vers un syscall direct.

SSI-VM est pertinent pour : Roblox/Luau, les addons WoW, les plugins serveur CS2, tout contexte Lua/Python embarqué où l'API bytecode est accessible.

---

## Le Modèle en Deux Phases de SSI

La recherche sur JavaScript a révélé que SSI se décompose naturellement en deux problèmes indépendants :

```
Phase 1 — Injection
  Les octets contrôlés par l'attaquant peuvent-ils apparaître dans une région exécutable ?
  Dépend de : existence de la frontière, heuristiques JIT, survie des constantes

Phase 2 — Exécution
  L'exécution peut-elle être redirigée vers ces octets ?
  Dépend de : fuite d'adresse, primitive d'écriture mémoire, modèle de sandbox
```

En C, les deux phases sont triviales — le compilateur place les octets à un offset connu, et la manipulation de pile redirige l'exécution.

En JavaScript/V8, la Phase 1 est confirmée atteignable. La Phase 2 est bloquée par trois barrières architecturales indépendantes :

- **Pointer compression** — les pointeurs heap sont des offsets 32 bits, pas des adresses utilisables.
- **Isolation de la région JIT** — aucune API JS n'expose les adresses dans la région de code JIT.
- **Absence de lecture mémoire arbitraire** — une primitive de type confusion (addrof) nécessite une CVE non patchée.

La conclusion pour SSI-JS : l'injection existe, mais V8 empêche sa traversée depuis JavaScript par conception, non par accident.

---

## Récapitulatif de la Surface d'Attaque

| Catégorie | Injection d'octets | Fuite d'adresse | Redirection d'exécution | Syscall |
|---|---|---|---|---|
| Compilé (C/Rust…) | ✓ trivial | ✓ natif | ✓ pile/ptr | ✓ |
| JIT — JS navigateur (V8) | ✓ confirmé | ✗ sandboxé | ✗ bloqué | ✗ |
| JIT — moteurs embarqués | ✓ probable | ◑ moins protégé | ◑ possible | ◑ |
| JIT — LuaJIT | ✓ probable | ◑ exposé par -jdump | ◑ pas de sandbox navigateur | ◑ |
| Interpréteur pur | ✗ impossible | N/A | N/A | ✗ |
| SSI-VM (bytecode) | opcodes VM uniquement | N/A | ✓ via load() | ✗ |

---

## Conclusion

SSI n'est pas une technique spécifique au C. C'est une classe d'attaque générale définie par une condition nécessaire unique : l'existence d'une frontière source-vers-exécutable dans le runtime cible.

Cette frontière est inconditionnelle dans les langages compilés, conditionnelle dans les langages JIT, et structurellement absente dans les interpréteurs purs. La puissance de l'attaque est ensuite bornée par la capacité de l'attaquant à localiser et rediriger l'exécution vers les octets injectés — un problème trivial en C, bloqué par le sandbox V8 dans les navigateurs, et potentiellement soluble dans des contextes JIT moins protégés comme les moteurs embarqués ou LuaJIT.

La décomposition en phase d'injection et phase d'exécution est l'insight fondamental : un runtime peut être partiellement vulnérable — injectable mais non exploitable — si seulement la Phase 1 est atteignable. V8 se trouve précisément dans cet état.

> **Loi d'applicabilité SSI :** Un runtime est susceptible à SSI si et seulement si une construction au niveau source détermine le contenu d'octets dans une région mémoire exécutable par le CPU. L'exploitabilité de cette susceptibilité est bornée par la capacité de l'attaquant à compléter la phase d'exécution.

---

## Directions de Recherche Ouvertes

- **WebAssembly comme pont d'exécution** — le modèle de mémoire linéaire de WASM et son constant blinding moins agressif pourraient offrir un chemin pour compléter la Phase 2 dans un contexte navigateur.
- **Moteurs JS non-V8** — QuickJS, Duktape, Hermes (React Native) n'ont pas de pointer compression ni de sandbox navigateur. SSI complet pourrait y être atteignable.
- **LuaJIT dans les moteurs de jeu** — utilisé dans des contextes (Roblox, nginx/OpenResty) où le modèle de sandbox est défini par l'application et potentiellement plus faible que V8.
- **Side-channel Spectre/timing** — `SharedArrayBuffer` + timer haute résolution peut faire fuiter des adresses mémoire arbitraires, fournissant potentiellement la primitive d'adresse nécessaire à la Phase 2 sans CVE.

---

*Ce travail a été réalisé dans un contexte purement éducatif et de recherche personnelle.*
