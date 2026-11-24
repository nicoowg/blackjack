# Kort

Blackjack i én side. Spil solo, eller lav et bord og send linket til dine venner.

**Spil:** https://nicoowg.github.io/blackjack/

- Navn og en 4-cifret kode, du selv vælger. Alle starter med 500 aura. Kontoen og auraen gemmes på den enhed, du spiller fra.
- **Solo** kører helt i din browser.
- **Bord** (op til 5): bordet kører i browseren hos den, der lavede det. Linket har en kode (`#ABCDE0`), og vennerne kommer ind ved at åbne det. Beskederne går gennem et gratis offentligt MQTT-relæ over wss, så det virker bag routere og på mobilnet. Lukker værten fanen, lukker bordet.
- Rigtige regler: 6 kortspil, dealeren står på alle 17, blackjack betaler 3 til 2, forsikring 2 til 1, dealeren kigger efter blackjack, doble på alle to kort (også efter deling), del op til 4 hænder, delte esser får ét kort, sen overgivelse.

Taster: 1-4 jetoner, mellemrum giv, H kort, G stå, D doble, P del, O giv op, F forsikring, N nej tak.
