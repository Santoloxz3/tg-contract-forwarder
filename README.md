# CA Courier: riconoscimento automatico e filtro su evidenze

Il filtro è sempre attivo prima dell'inoltro, anche in dry-run. Non usa chiavi,
firme o transazioni. Pannello e verifica manuale riconoscono automaticamente
EVM (Ethereum, BNB Chain, Base), Solana e Sui. Le informazioni nel pannello
elencano controlli, avvisi, blocchi e limiti per ogni rete.

## Modalità rapida (balanced, default)

Blocca il contratto MCPAD già verificato malevolo, honeypot rilevati, restrizioni
di acquisto/vendita rilevate, token non trasferibili, stato iniziale degli account
congelato/non utilizzabile, pausa nativa attiva e commissioni note oltre soglia.
Il risultato è una restrizione rilevata, non una prova generale di truffa.

Capacità amministrative (blacklist, freeze authority, mint, tasse modificabili,
proxy, delegato permanente, chiusura mint, hook, upgrade, metadati), reputazione,
liquidità scarsa/assente e dati mancanti sono **avvisi**. Le API indisponibili e i
timeout autorizzano l'inoltro con `allowed_with_warnings`: il rischio resta
non verificato. Indirizzi invalidi, indirizzi che RPC identifica come account
anziché mint e identità ambigue/non risolvibili non vengono inoltrati.

- **EVM:** GoPlus sulle tre reti in parallelo; Dexscreener aggiunge identità e
  liquidità se pronto. Honeypot, cannot_sell_all, cannot_buy e tasse note oltre
  soglia bloccano. Gli altri flag e i campi assenti producono avvisi. Non c'è
  simulazione obbligatoria. Una fonte positiva può chiudere il controllo dopo
  una finestra di 30 ms; reti lente restano esplicitamente non verificate.
- **Solana:** GoPlus e RPC `getAccountInfo` partono insieme. SPL/Token-2022,
  inizializzazione, autorità, trasferibilità, stato account ed estensioni sono
  analizzati. Commissioni attuali/programmate sono verificate sui basis point
  nativi. Lo scanner può restituire unità discordanti rispetto alla documentazione:
  in quel caso si attende RPC entro il budget e si segnala l'incertezza se assente.
  Poteri amministrativi sono avvisi. `nonTransferable`, default state restrittivo,
  `pausableConfig.paused=true` e commissioni native oltre soglia bloccano.
  Nessuna simulazione vendita o verifica di freeze di un wallet specifico.
- **Sui:** si preserva `package::modulo::TOKEN`; un package nudo si risolve solo
  con una coin univoca. GoPlus verifica DenyCap/blacklist, mint, upgrade e metadati:
  sono avvisi in modalità rapida. Nessuna verifica di blacklist sul wallet,
  simulazione vendita, liquidità, commissioni o routing. Maestro non supporta
  Sui: il filtro può verificare la coin, ma la destinazione Maestro ferma l'inoltro.

## Modalità prudente (strict, opzionale)

EVM richiede pool, liquidità minima, tutti i flag GoPlus e Honeypot.is con
simulazione, identità/rete/pool, tasse, limiti, codice e rischio verificati.
I poteri amministrativi e i dati essenziali mancanti bloccano. Solana blocca
freeze/mint, hook, delegato, chiusura mint, modifiche delle commissioni, pausa/burn;
Sui blocca DenyCap, mint e upgrade. Le unità scanner ambigue richiedono conferma
nativa. Nessuna simulazione usa il wallet/importo del bot destinatario.

## Tempi e persistenza

Il preset richiesto viene applicato una sola volta al primo avvio v3:
modalità rapida, rete automatica, delay tecnico **1 s**, budget **2,5 s**.
Le successive modifiche dal pannello persistono normalmente. Sorgente,
destinazione, dry-run, storico, duplicati e altre soglie sono preservati.

Le richieste partono in parallelo senza attese per età del token, holder,
indicizzazione o migrazione pool. Il delay si sovrappone al controllo:
il tempo nominale è `max(delay, durata controllo)`, non la somma. Il budget
è regolabile da 1 a 10 s, il delay da 0 a 30 s. La tassa massima resta 10%,
regolabile 0–20%; liquidità EVM $10.000 è un avviso in modalità rapida.

Le richieste residue vengono cancellate e non ci sono job periodici o cache
positive. Dopo FloodWait si ripete il controllo; configurazione cambiata o attesa
oltre 120 s scartano il messaggio. Storico SQLite conserva esiti, avvisi, dati e
millisecondi. La verifica manuale autenticata `POST /api/security/check` deduce
la rete dall'indirizzo e non inoltra nulla. Il comando rimane `python runner.py`.
RPC opzionali: `SOLANA_RPC_URL`, `SUI_RPC_URL`.

Nessun controllo garantisce sicurezza, profitto, assenza di rug pull o vendibilità
futura. In modalità rapida il vantaggio temporale comporta controlli incompleti:
non si attende necessariamente ogni fonte e un rischio può non essere rilevato.
