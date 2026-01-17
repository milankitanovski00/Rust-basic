# My second blockchain - objasnjenje koda

## Cargo.toml zavisnosti i use importi

Zavisnosti u Cargo.toml

```
chrono = "0.4"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
sha2 = "0.10.0"
hex = "0.4.3"`
```

Ovo govori Cargo-u:“Ovaj projekat zavisi od ovih biblioteka i njihovih verzija.”

Kako znaš koje ti trebaju? <br>
Na osnovu funkcionalnosti koje želiš: <br>
| Šta želiš | Biblioteka |
| ----------------------- | ------------ |
| Vreme / timestamp | `chrono` |
| Serijalizacija struct-a | `serde` |
| JSON format | `serde_json` |
| SHA-256 hash | `sha2` |
| Hex string iz bajtova | `hex` |

Verzije:

- Uzimaš sa crates.io
- Obično latest stable
- Rust Book / tutorijali često napišu koje verzije koriste

## Importi u main.rs

```
use chrono::Utc;
```

Koristiš UTC vreme <br>

```
use serde::{Deserialize, Serialize};
```

Omogućavaš da struct može:

- da se pretvori u JSON (Serialize)
- da se vrati iz JSON-a (Deserialize)

```
use sha2::{Digest, Sha256};
```

Sha256 = hash algoritam <br>
Digest = trait koji daje metode (update, finalize) <br>
`trait je način za definisanje deljene funkcionalnosti (apstraktnog interfejsa)`

```
use hex::encode;
```

Pretvara bajtove u čitljiv hex string

## Struct Block

```
#[derive(Serialize, Deserialize, Debug, Clone)]
```

Ovo je automatsko generisanje koda za tvoj struct.
| Trait | Šta omogućava |
| ------------- | -------------------- |
| `Serialize` | struct → JSON |
| `Deserialize` | JSON → struct |
| `Debug` | `println!("{:?}")` |
| `Clone` | `.clone()` kopiranje |

Bez ovoga, Rust ne zna kako da radi te stvari sam.

### pub blocks: Vec<Block> VS vec![]

```
Vec<Block>
```

TIP - “Ovo je vektor koji sadrži Block elemente” <br>
Koristi se u struct definiciji.

```
vec![]
```

MAKRO - “Kreiraj prazan Vec”

Primer:

```
let blocks = Vec::new();
let blocks = vec![];
```

Ne možeš koristiti vec![] kao tip.

### usize

usize je tip

Unsigned integer
Veličina zavisi od arhitekture:

- 64-bit → u64
- 32-bit → u32

Koristi se za:

- indekse
- dužine
- iteracije

### `serde_json::to_string(&self)

```
let json = serde_json::to_string(&self)
    .expect("Cannot serialize to json");
```

<b>serde_json biblioteka </b><br>
serde_json služi za pretvaranje Rust struct-ova u JSON string i nazad, što je potrebno da bi se podaci mogli lako čuvati, slati ili heširati.

Šta radi?

1. &self → referenca na ceo struct
2. to_string → pretvara struct u JSON string
3. expect(...) → ako dođe do greške → panic

Bez Serialize trait-a → ovo ne radi.

### SHA-256 hashing linije

```
let mut hasher = Sha256::new();
```

Kreira novi SHA-256 objekat

```
hasher.update(json);
```

Ubacuje podatke za hash (JSON string)

<b>Zašto je potrebno raditi hasher.update(...) </b> <br>
update ubacuje podatke u hash algoritam jer bez toga ne bi imao šta da se hešira.

```
encode(hasher.finalize())
```

Računa hash <br>
Pretvara bajtove u hex string <br>
`finalize() → Vec<u8>` <br>
`encode() → "a3f9c1..."`

### pub fn new(difficulty: usize) -> Self

<b>✔️ ISPRAVNO </b>

```
pub fn new(difficulty: usize) -> Self
```

Vraća vrednost (Blockchain)

<b> ❌ POGREŠNO </b>

```
pub fn new(difficulty: usize) -> &Self
```

Zašto?

- bc je lokalna promenljiva
- Posle izlaska iz funkcije → ne postoji
- Rust ne dozvoljava dangling reference

<b>Zašto new() ne vraća referencu (&Self) </b> <br>
Ne može se vratiti referenca jer bi pokazivala na lokalnu promenljivu koja prestaje da postoji čim funkcija završi.

Konstruktor uvek vraća Self, ne referencu.

### timestamp: Utc::now().timestamp()

```
Utc::now()
```

Trenutno vreme (UTC)

```
.timestamp()
```

Broj sekundi od 1.1.1970 (UNIX epoch)
Koristi se za:

- redosled blokova
- proveru validnosti

### Da li je ovo konstruktor?

```
let mut bc = Self { blocks: Vec::new(), difficulty };
```

Da, u Rust smislu <br>
Rust nema klasične konstruktore, ali:

- new() metoda
- koja vraća Self
- ponaša se kao konstruktor

`Self = Blockchain`

### let Some(last_block) = self.blocks.last() else { return; };

Ovo je moderni Rust pattern matching.

<b>Šta vraća last()? </b>

```
Option<&Block>
```

Značenje:

- Ako postoji → smesti u last_block
- Ako ne → return

last_block je &Block

### last_block.hash.clone()

<b>Zašto clone()?</b>

- hash je String
- String nije Copy
- ne smeš pomeriti vrednost iz borrowed struct-a

clone() pravi duboku kopiju

### previous_hash: last_block.hash.clone(), VS previous_hash = last_block.hash

Ovo je čisto ownership pitanje u Rust-u, i razlika je ogromna, iako izgleda sitno.

<b>✔️ ISPRAVNO</b>

```
previous_hash: last_block.hash.clone(),
```

Zašto?

- last_block je pozajmljen (&Block)
- hash je String (nije Copy - on je za brojeve...)
- .clone() pravi novi String koji pripada novom bloku
  bezbedno i ispravno

<b>❌ NEISPRAVNO</b>

```
previous_hash = last_block.hash
```

Zašto ovo ne može?

1. last_block je &Block
2. hash je vlasništvo Block-a
3. Rust ne dozvoljava da:

- izvučeš (move) String
- iz pozajmljene strukture

`Ne može zato što bi time „uzeo“ hash iz starog bloka, a taj stari blok bi ostao bez svog podatka, što Rust ne dozvoljava jer bi moglo da napravi grešku.`

### {:?} vs {:#?}

```
{:?}   // jedna linija
{:#?}  // lepo formatiran (multi-line)
```

{:#?} je bolji za debug velikih struct-ova

### Da li kod 1..self.blocks.len() se racuna prvi element?

Ne, ne treba da računaš prvi element.

Zašto?

- blok 0 = genesis block
- nema prethodni blok
- validacija počinje od 1

```
for i in 1..self.blocks.len() {
```

✔️ Ovo je namerno i ispravno
