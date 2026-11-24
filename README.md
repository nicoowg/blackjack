# Kort

Blackjack i én fil, til solo eller ved et fælles bord med venner over et link.

- Login med navn og en 4-cifret kode, du selv vælger. Alle starter med 500 aura.
- Solo eller Bord (op til 5 spillere). Serveren styrer kort, regler og aura, så ingen kan snyde fra browseren.
- Rigtige regler: 6 kortspil, dealeren står på alle 17, blackjack betaler 3 til 2, forsikring 2 til 1, dealeren kigger efter blackjack, doble på alle to kort (også efter deling), del op til 4 hænder, delte esser får ét kort, sen overgivelse.

```
node server.mjs          # port 7761, starter selv en cloudflared-tunnel og laver et link
KORT_NOTUNNEL=1 node server.mjs   # kun lokalt
```

Kræver kun Node. Konti gemmes i `~/.kort/konti.json` (koden som scrypt-hash).

Taster: 1-4 jetoner, mellemrum giv/stå, K kort, S stå, D doble, P del, G giv op.
