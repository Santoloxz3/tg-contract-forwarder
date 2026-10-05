# CA Courier: controllo preventivo prima di Maestro

Il listener verifica ogni CA **prima** di `send_message`. Il filtro è sempre attivo,
anche in dry-run. Un esito `unknown`, un timeout, una risposta incompleta o un errore
impediscono l'inoltro. Nessuna chiave privata, firma o transazione è necessaria.

## Copertura e limiti

- EVM: Ethereum (1), BNB Chain (56), Base (8453). In modalità automatica la rete
  viene identificata dalle pool Dexscreener; una rete assente/ambigua viene bloccata.
- Solana, Sui e le altre reti sono **bloccate perché non verificate**, non autorizzate
  implicitamente. L'abilitazione del tipo di address non disabilita questo vincolo.
- Dexscreener individua la pool e la liquidità disponibile; GoPlus controlla i rischi
  del contratto; Honeypot.is fornisce una simulazione acquisto/vendita sulla stessa pool.
  Non si forza una liquidità simulata e non si riutilizzano esiti positivi in cache.
- Nessuna garanzia di profitto, di liquidità bloccata, di assenza di rug pull o di
  vendibilità futura. Gli scanner possono sbagliare. La simulazione esterna non usa
  il wallet dell'utente o l'importo impostato su Maestro. Non è un audit completo del codice.
- Il token MCPAD già analizzato è inoltre nella lista locale dei contratti bloccati.

## Regole

Blocchi per blacklist, whitelist, pausa trasferimenti, tasse modificabili (anche per
wallet), saldi modificabili, mint, proxy, proprietario nascosto/recuperabile,
autodistruzione, chiamate esterne, restrizioni di acquisto/vendita, limiti modificabili
e cooldown. Si richiedono risposte esplicite per tutti i controlli: campi vuoti,
mancanti o malformati non equivalgono a rischio zero. La rinuncia all'ownership non
basta a ignorare blacklist esistenti o funzioni pubbliche malevole.

Il filtro è deliberatamente restrittivo e può bloccare anche token legittimi che
hanno questi poteri. `allowed` significa soltanto «controlli disponibili superati».

## Pannello e persistenza

Impostazioni salvate nel SQLite esistente:

| Impostazione | Default | Intervallo |
|---|---|---|
| Rete | auto | auto, 1, 56, 8453 |
| Tassa massima | 10% | 0–20% |
| Liquidità minima sulla pool | $10.000 | $1.000–$1.000.000 |

Il registro contiene `security_blocked`, `security_unknown`, `security_test` e
`stale_ignored`; ogni evento conserva il report completo in `security_json`.
La migrazione aggiunge una colonna senza eliminare storico, impostazioni o duplicati.
I CA bloccati non vengono marcati come inoltrati. Nessun job periodico: le richieste
esterne avvengono solo alla ricezione di un CA nuovo o durante una verifica manuale.

`POST /api/security/check` è autenticato come il pannello, verifica soltanto e **non
inoltra messaggi**. Il pannello mostra gli esiti completi. Se le API limitano le
richieste o non rispondono, il risultato resta `unknown` e il listener non invia.

Le verifiche hanno un limite complessivo di 22 secondi; i CA in attesa da più di 120
secondi vengono scartati. Dopo un FloodWait Telegram serve una nuova verifica.
Una modifica della configurazione durante l'attesa annulla l'inoltro in corso.

## Verifica e rilascio

```sh
python -m pip install -r requirements.txt
python -m unittest -q test_security
python -m py_compile main.py token_security.py
```

I test usano un client Telegram finto: coprono i blocchi senza tentativi di invio,
gli esiti incompleti, il controllo manuale, la migrazione SQLite, i duplicati,
il dry-run, un cambio configurazione in corso e la nuova verifica dopo FloodWait.

Railway segue `main` e continua ad avviare `python runner.py`. Non occorrono nuove
variabili né modifiche alle credenziali. `/health` espone `version=security-gate-v1`,
`security_enabled=true` e `security_fail_closed=true` per verificare il rilascio.

Rollback: ripristinare i file dal commit precedente e pubblicare il ripristino.
Il vecchio codice ignora la colonna SQLite aggiunta; lo storico resta leggibile.
Attenzione: il rollback rimuove il filtro e ripristina il vecchio inoltro senza controlli.
