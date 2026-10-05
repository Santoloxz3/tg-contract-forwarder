# CA Courier: filtro multichain prima dell’inoltro

Il controllo è sempre attivo prima di inviare un CA al bot di destinazione, anche
in dry-run. Non usa chiavi private, firme né transazioni. La configurazione viene
salvata nel SQLite esistente, senza eliminare storico o duplicati.

## Modalità Bilanciata (default)

Blocca restrizioni concrete: blacklist/congelamento, non trasferibilità, vendite
impedite, modifiche ai saldi, tasse per wallet e commissioni note oltre soglia.
L’assenza di un controllo **essenziale** resta `unknown` e non autorizza l’inoltro.
Dati secondari mancanti, mint, metadati modificabili, liquidità non indicizzata e
certi poteri amministrativi diventano avvisi, non un rifiuto automatico.

`allowed_with_warnings` significa che i controlli essenziali disponibili sono stati
superati con copertura e rischi residui esplicitati nel registro. Non significa
che il token è sicuro, vendibile in futuro o profittevole.

### Solana

- GoPlus Solana e RPC `getAccountInfo` con `jsonParsed` partono in parallelo.
- Un risultato completo sui controlli essenziali basta; una seconda fonte già
  disponibile può aggiungere un blocco. Non si attende una fonte lenta oltre
  una finestra aggiuntiva di 100 ms. Le richieste residue vengono annullate.
- La lettura nativa verifica che sia un mint inizializzato di SPL Token o Token-2022,
  freeze authority ed estensioni. Blocchi per hook attivi, delegato permanente,
  token non trasferibile, account congelati, pausa, commissioni modificabili,
  possibilità di chiudere il mint e altre estensioni restrittive. Estensioni
  sconosciute impediscono di considerare completo il controllo nativo.
- Non richiede DEX già indicizzato, un numero minimo di holder o pool migrata.
  Un lancio su bonding curve non viene respinto soltanto perché manca una pool.
- Mint authority e metadati modificabili sono avvisi. In modalità Prudente la
  mint authority è bloccante.

### Sui

- GoPlus Sui verifica la blacklist/DenyCap sul tipo completo della coin.
- `package::modulo::TOKEN` mantiene maiuscole e minuscole di modulo e tipo.
- Un package nudo viene risolto via RPC quando individua una sola coin con witness
  standard e metadati disponibili. Package ambigui, witness non standard o errori
  RPC richiedono il tipo completo. Le chiamate JSON-RPC Sui sono una compatibilità
  con i nodi che le espongono; una loro indisponibilità non autorizza a indovinare il tipo.
- DenyCap/blacklist bloccanti; mint, upgrade e metadati sono avvisi in modalità
  Bilanciata. Prudente blocca anche mint e upgrade e richiede i relativi esiti.
- **Maestro non elenca Sui tra le reti supportate**: la verifica Sui è disponibile,
  ma se la destinazione è Maestro non viene effettuato l’inoltro. Il registro
  mostra `unsupported_destination`. Una destinazione diversa va configurata nel
  pannello; il filtro non verifica le capacità di trading di bot terzi.

### EVM

- Ethereum, BNB Chain e Base. Rete esplicita consigliata quando nota: una richiesta
  GoPlus invece di tre per identificare il token senza attendere Dexscreener.
- In automatico si interrogano le tre reti in parallelo. Risposte ambigue o
  identificazione incompleta non autorizzano l’inoltro.
- GoPlus deve verificare almeno honeypot, blacklist, pausa trasferimenti, modifica
  saldi e tasse per wallet. Segnali positivi di proxy, proprietario nascosto,
  autodistruzione e restrizioni di acquisto/vendita sono bloccanti.
- In Bilanciata, liquidità non indicizzata/sotto soglia, mint, whitelist e tasse
  globali modificabili sono avvisi. Quest’ultima scelta aumenta il rischio di
  peggioramenti delle tasse dopo l’acquisto. Non c’è simulazione obbligatoria.
- Prudente mantiene i controlli completi GoPlus + Honeypot.is, verifica la pool e
  impone la soglia di liquidità. Non è una simulazione del wallet/importo Maestro.
- Il contratto MCPAD già analizzato resta sempre bloccato localmente.

## Tempismo e impostazioni

| Impostazione | Default | Intervallo |
|---|---|---|
| Modalità | Bilanciata | Bilanciata / Prudente |
| Budget complessivo verifiche | 4 s | 1–10 s |
| Rete EVM | auto | auto, 1, 56, 8453 |
| Tassa massima | 10% | 0–20% |
| Soglia liquidità EVM | $10.000 | $0–$1.000.000 |

Il budget limita l’attesa, non garantisce il tempo di risposta delle API. Il delay
tecnico già configurato è separato e si aggiunge alle verifiche. Non ci sono attese
per indicizzazione, cache di esiti positivi o job periodici. Dopo FloodWait serve
un nuovo controllo; messaggi in attesa da oltre 120 s o con configurazione cambiata
vengono scartati. È possibile perdere l’occasione quando un controllo essenziale
non risponde nel tempo assegnato: il filtro non confonde rapidità con autorizzazione
su dati assenti.

Il registro conserva esito, avvisi, copertura e durata in millisecondi quando la
verifica termina. `POST /api/security/check` è autenticato, supporta tutte e tre le
famiglie di reti e **non inoltra messaggi**. I CA respinti non sono marcati inoltrati.
Le credenziali esistenti e il comando `python runner.py` restano utilizzabili.

RPC opzionali: `SOLANA_RPC_URL` e `SUI_RPC_URL`; default pubblici di mainnet.
Non occorrono nuove variabili per il rilascio. Le API pubbliche possono imporre
rate limit. In modalità rapida una fonte che completa i controlli essenziali può
bastare; una fonte lenta potrebbe quindi non essere consultata fino in fondo.

## Limiti

Non è un audit completo, non effettua una vendita di prova, non controlla il wallet
utente né la dimensione dell’acquisto Maestro. Non garantisce assenza di rug pull,
liquidità bloccata, vincoli del protocollo di lancio, slippage o profitto. Gli scanner
possono sbagliare e il rischio può cambiare dopo il controllo. Sugli asset Sui la
lettura dei poteri del token non verifica routing, pool o capacità del bot di trading.

## Validazione e rilascio

```sh
python -m pip install -r requirements.txt
python -m unittest -q test_security test_multichain
python -m py_compile main.py token_security.py non_evm_security.py
```

I test usano Telegram finto. Coprono blocchi senza invio, fallback nativo per token
non indicizzati, timeout, estensioni restrittive, avvisi non bloccanti, case e
ambiguità Sui, destinatario Maestro non compatibile, duplicati, dry-run e FloodWait.
Railway segue `main`; `/health` espone `version=security-gate-v2`, reti e modalità.
La tabella degli eventi conserva i report nella colonna `security_json`.

Ripristinare un commit precedente permette il rollback senza cancellare il DB.
Tornare a un commit privo del filtro ripristina l’inoltro senza controlli.
