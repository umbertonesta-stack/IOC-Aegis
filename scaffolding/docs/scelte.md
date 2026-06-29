# Scelte implementative

> Dove racconti le decisioni non ovvie: cosa hai scelto, perché, e cosa hai scartato.
> È il documento che il docente legge per capire se hai *progettato* o solo *programmato*.

## Perché l'ereditarietà (e non composizione/funzioni)

_Paragrafo obbligatorio._ Spiega perché la tua gerarchia è una relazione *is-a* reale e
perché qui l'ereditarietà è la scelta giusta rispetto alle alternative:

- avresti potuto usare una sola classe con un `if`/`match` sul tipo? Perché non l'hai fatto?
- avresti potuto usare la composizione (un oggetto che ne contiene un altro)? Perché no?
- dove sfrutti concretamente il polimorfismo nel resto del codice?

## Altre scelte non ovvie

- _Struttura dati X invece di Y perché…_
- _Gestione degli errori: …_
- _Compromessi accettati per stare nei tempi: …_

## Alternative scartate

_Cosa avete provato e abbandonato, e perché. Anche i vicoli ciechi insegnano._
