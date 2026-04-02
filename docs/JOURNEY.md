# LoL Private Server - Journal de Reverse Engineering

## Objectif
Créer un serveur privé League of Legends compatible avec le client moderne (patch 16.6) pour jouer en local.

---

## Jour 1 — 31 Mars 2026

### Phase 1 : Capture du trafic réseau

**NetHook DLL (version.dll proxy)**
- Déployé `version.dll` hook dans `client-private/` (copie privée du client)
- Hook intercepte `sendto`/`WSASendTo`/`recvfrom`/`WSARecvFrom` dans `ws2_32.dll`
- Le client envoie des paquets de **519 bytes**, tous chiffrés
- Leçon : **JAMAIS toucher au LoL officiel ni à Vanguard**

**Capture Wireshark réussie : 67 MB de trafic réel**
- Serveur Riot : `162.249.72.5:7342`
- Clé Blowfish : `jNdWPAc3Vb5AyjoYdkar/g==`
- 33,000+ paquets capturés pendant ~21 minutes

**Découvertes clés :**
- LNPBlob = `[4B magic 0x37AA0014][4B SessionID]` → premiers 8 bytes de chaque paquet client
- Structure des paquets identifiée (header, payload chiffré, footer)

### Phase 2 : Tentatives de déchiffrement (TOUTES ÉCHOUÉES)

| Tentative | Résultat |
|-----------|----------|
| Blowfish ECB | Pas de match |
| Blowfish CBC (~40 IVs) | Pas de match |
| Blowfish OFB/CFB (IV=0) | Premier byte OK (0x83) mais suite fausse |
| AES-GCM/CTR | Rien |

### Phase 3 : Analyse du binaire

- **x64dbg + ScyllaHide** : stub.dll détecte le debugger → crash
- **Frida** : `ProcessNotRespondingError` — stub.dll bloque l'injection
- **Hook kernel32** : crash immédiat — stub.dll vérifie l'intégrité
- **NOP BF_cfb64_encrypt** : crash — guard pages sur .text

### Phase 4 : Ghidra — Analyse statique

- P-box xrefs → `BF_set_key` (FUN_1410ec460)
- Call chain : FUN_140601920 → FUN_14058b8d0 → BF_set_key
- IV initialisé à 0 dans FUN_14058b8d0 ✅
- **BF_cfb64_encrypt** (FUN_1410f2ce0) : 4 callers, TOUS pour spectateur/replay
- Le sendto est à LoLPrivate.exe +0x58ECBB, pas dans RiotGamesApi.dll

---

## Jour 2 — 1er Avril 2026

### Phase 5 : PERCÉE — Double CFB découvert

**Découverte majeure via Ghidra :**
- FUN_1410f2a10 : Double CFB decrypt → CFB_decrypt → reverse ALL bytes → CFB_decrypt
- FUN_1410f41e0 : Double CFB encrypt → CFB_encrypt → reverse ALL bytes → CFB_encrypt
- Clé = `17BLOhi6KZsTtldTsizvHg==` de gameconfig.json (pas la clé Riot !)
- IV = 0 pour chaque paquet (frais)

**Vérification :**
- P-box + S-box capturés depuis la mémoire du process → match byte-for-byte
- Double CFB roundtrip sur données client réelles → **PARFAIT**

### Phase 6 : Echo handshake fonctionne

- Serveur renvoie les propres données du client (bytes 8-518)
- Le client accepte via un bypass memcmp (ring buffer)
- Séquence echo : 519 → 119 → 64 → 34 → 27 → 19B
- Client atteint l'état **"Hard Connect"** ✅

### Phase 7 : CRC nonce — Le dernier obstacle

**Problème :** Les paquets non-echo sont rejetés par FUN_1405725f0 (CRC check)

**Analyse Ghidra de la chaîne CRC :**
- FUN_140588f70 : construit un struct sur la stack
- FUN_1405725f0 : appelle FUN_140577f10(param_1) pour calculer le CRC attendu
- Comparaison : `iVar20 == FUN_140577f10(param_1)` → si faux, paquet rejeté

### Phase 8 : Tentatives de bypass CRC — TOUTES BLOQUÉES

| Méthode | Résultat |
|---------|----------|
| VirtualProtect sur .text | err=5, ACCESS_DENIED (guard pages) |
| Hardware breakpoints (DR0/DR7) | GetThreadContext retourne FALSE pour les DR |
| TF trap flag + VEH | stub.dll VEH intercepte SINGLE_STEP avant nous |
| RaiseException custom | VEH pas déclenché |
| Frida attach/spawn | "refused to load frida-agent" |
| WriteProcessMemory externe | VirtualProtectEx échoue |
| Fake stub.dll | Integrity check → crash instant |
| Patch binaire sur disque | Hash check → "Crash Dump" |
| **Cheat Engine kernel driver** | **Bloqué par Windows driver blocklist** |

### Phase 9 : Calcul du CRC nonce correct

**Struct CRC sur la stack de FUN_140588f70 :**

| Offset | Variable | Valeur |
|--------|----------|--------|
| 0x00 | local_c8 | `*(conn+0x138)` = 1 |
| 0x08 | local_c0 | 0 |
| 0x18 | local_b0 | 0xFFFFFFFFFFFFFFFF |
| 0x48 | local_80 | NULL (pas de payload) |
| 0x52 | — | 0 (payload length) |

**Ordre de traitement :** byte[8], byte[9], byte[0..7], local_res10[0..7]

**Nonce calculé = `~crc = 0x8DFE1964`** ✅

Le serveur a été mis à jour avec ce nonce correct.

### Phase 10 : Préparation CE kernel driver

- Registre Windows modifié : `VulnerableDriverBlocklistEnable = 0`
- Script Lua prêt : `ce_kernel_patch.lua`
- **REBOOT NÉCESSAIRE** pour que la modification prenne effet

---

## Jour 2 (suite) — 2 Avril 2026

### Phase 11 : Client launch corrigé

**Découverte :** Le client nécessite des arguments complets pour fonctionner :
```
-Product=LoL -PlayerID=1 -GameID=1 -LNPBlob=N6oAFO++rd4=
-GameBaseDir=D:\LeagueOfLegendsV2\client-private -Region=EUW
-Locale=fr_FR -SkipBuild -EnableCrashpad=false
```
Sans ces args → "Failed to extract information from command line string" → exit immédiat.

**Découverte :** Le serveur doit être lancé avec `--rawudp` (pas le mode LENet auto-detect qui cycle les protocoles et rate les paquets client).

### Phase 12 : Nettoyage git + push

- Fichiers massifs retirés de l'historique (client-private/ = 3.3 Go, ghidra_project/ = 2+ Go)
- .gitignore mis à jour pour exclure client-private/, ghidra_project/, ghidra/, jdk*, mingw64/, *.zip
- Push réussi sur GitHub

---

## Résumé — État actuel

### RÉSOLU ✅
1. Client lance et charge les assets
2. Encryption Blowfish Double CFB crackée et vérifiée
3. Echo handshake fonctionne → "Hard Connect"
4. CRC nonce calculé correctement (0x8DFE1964)
5. Format complet des paquets reverse-engineered
6. Toutes les fonctions Ghidra clés identifiées

### EN COURS ⏳
7. CRC bypass via CE kernel driver (après reboot)

### À FAIRE ❌
8. Paquets de game init (KeyCheck, StartGame)
9. Loading screen
10. Gameplay (165 champions, 138 items déjà codés)

---

## Jour 3 — 2 Avril 2026

### Phase 1 : Tentatives CRC bypass (TOUTES échouées)
- CE kernel patch : VulnerableDriverBlocklist désactivé, reboot OK, mais Vanguard kernel bloque les écritures même via CE
- NtProtectVirtualMemory direct syscall (0x50 lu depuis ntdll sur disque) : STATUS 0xC000004E (Vanguard intercepte au kernel)
- NtWriteVirtualMemory direct syscall : STATUS_PARTIAL_COPY
- Hardware breakpoints : stub.dll intercepte GetThreadContext/SetThreadContext
- Verdict : **AUCUNE méthode ring-3 ne peut patcher le CRC check**

### Phase 2 : PERCÉE — Echo-all via recvfrom hook
- Idée : au lieu de patcher le CRC, contourner en renvoyant les propres données du client
- Le hook version_proxy.c capture chaque sendto et le retourne via recvfrom (strip 8B LNPBlob header)
- Résultat : **handshake complet !** 519B→119B→64B→34B→27B→19B
- Le client atteint l'état **CONNECTED** et maintient avec des pings 19B/27B

### Phase 3 : Tracing du pipeline complet
- Installé Ghidra 11.3.2 complet + Java JDK 21 + MSYS2/MinGW
- Trouvé le VRAI host struct par scan de la stack (matching *(ptr+0x38)==socket)
- plVar15 = *(host+0x20) — l'objet handler NON-NULL !
- vtable[0x28] = RVA 0x573160 (FUN_140573160) — le handler CRC confirmé
- **Pipeline tracé de bout en bout** :
  1. recvfrom → FUN_140588f70 (CRC/decrypt)
  2. → FUN_140573160 (vtable handler, enqueue)
  3. → FUN_140589a90 (producer: ring buffer)
  4. → FUN_1405883d0 (consumer: dequeue loop)
  5. → dispatch: CALL [RAX+0x10] via *(plVar15+0x128)

### Phase 4 : KeyCheck injection (ne marche pas encore)
- P[0]=0xBBCD2876 confirmé (match client)
- CRC nonce computation confirmée via FUN_140577f10 du client
- Queue slot montre cmd=6 (SEND_RELIABLE) à l'offset correct +0x1B
- KeyCheck injecté (encrypted + raw) : le client ne réagit pas
- Direct dispatch call → crash initial (double déréférencement vtable)

### Phase 5 : Consumer dispatch deep dive
- Consumer FUN_1405883d0 déqueue et dispatch via CALL [RAX+0x10]
- +0x128 et +0x168 : **STUBS** (GetDefaultSettings=return, return 1)
- **VRAI handler** trouvé à +0x160 : FUN_14057dce0 (RVA 0x57DCE0)
- Fix vtable read : *(plVar15+0x160) EST directement le vtable (pas double deref)
- **Direct dispatch RÉUSSI** : fn(plVar15, &key=0) → returned OK, pas de crash !
- FUN_14056e310 = std::map insert dans plVar15+0x150
- +0x128 vtable INCHANGÉ après l'appel (stubs permanents)
- **Prochaine étape** : trouver qui lit le std::map à +0x150 (game logic consumer)

### Statistiques mises à jour
- ~70 scripts Ghidra écrits et exécutés
- ~20 variantes du hook DLL compilées et testées
- ~40 combinaisons IV/mode crypto testées
- 12+ méthodes de bypass CRC tentées (TOUTES échouées, contourné par echo)
- 67 MB de trafic réel capturé
- Double CFB + CRC nonce + pipeline complet reverse-engineered
- Client CONNECTED via echo-all ✓
- Consumer dispatch identifié mais pas encore appelable ✗
