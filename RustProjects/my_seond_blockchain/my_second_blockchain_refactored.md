# Refaktorisan kod

## Kod pre refaktorizacije - struct Block

```
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub id: u64,
    pub hash: String,
    pub previous_hash: String,
    pub timestamp: i64,
    pub data: String,
    pub nonce: u64,
}

impl Block {
    // Calculate the block's hash
    pub fn calculate_hash(&self) -> String {
        let json = serde_json::to_string(&self).expect("Cannot serialize to json");
        let mut hasher = Sha256::new();
        hasher.update(json);
        encode(hasher.finalize())
    }
}
```

## Kod posle refaktorizacije - Block.rs

```
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use hex::encode;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub id: i64,
    pub hash: String,
    pub previous_hash: String,
    pub timestamp: i64,
    pub data: String,
    pub nonce: u64,
}

impl Block {
    pub fn new(
        id: u64,
        previous_hash: String,
        data: String,
        nonce: u64,

    ) -> Self {
        let mut block = Self {
            id,
            timestamp: Utc::now().timestamp(),
            previous_hash,
            data,
            nonce,
            hash: String::new(),
        };
        block.hash = calculate_hash();
        block
    }
    pub fn calculate_hash(&self) -> String{
        let json = serde_json::to_string(&self).expect("cannot serialize block to json");
        let mut hasher = Sha256::new();
        hasher.update(json);
        encode(hasher.finalize())
    }
}
```

> Razlika u kodu postoji zato što je logika namerno premeštena u Block, pa se blok sada sam pravilno napravi, umesto da to radi Blockchain.

Pre refaktorisanja:

- Blockchain je radio:
- pravljenje bloka
- računanje hash-a
- čuvanje blokova
  previše odgovornosti na jednom mestu

Posle refaktorisanja:

- Block:

  - zna kako se pravi
  - zna kako se hash računa

- Blockchain:

  - zna kada se blok dodaje
  - zna kako se blokovi povezuju
  - zna kako se lanac proverava

Zato se implementacija menja, ali ponašanje ostaje isto.

<b>Konkretan primer razlike</b>

<b>Pre</b>

```
let mut new_block = Block {
    ...
};
new_block.hash = new_block.calculate_hash();
```

<b>Posle</b>

```
let new_block = Block::new(...);
```

Logika nije nestala <br>
Samo je premeštena tamo gde pripada

---

### main.rs (stara verzija)

```
        let mut new_block = Block {
        id: ...,
        previous_hash: ...,
        data: ...,
        nonce: 0,
        hash: String::new(),
    };
    new_block.hash = new_block.calculate_hash();
```

> Rust ne zna ništa posebno o Block-u osim što je struct <br>
> Kod koji pravi blok je tu gde je i Blockchain <br>
> Možeš direktno da praviš blok “ručno”, jer sve što je potrebno je dostupno u istom fajlu <br>
> Zato ti nije bila potrebna funkcija new() — mogli smo da inicijalizujemo struct “ručno” <br>

### block.rs

> `pub fn new(...) -> Self` je idiomatični Rust “konstruktor”.
> Rust nema klasične konstruktore kao u Javi ili C++, ali ovakav new metod je standardni način da kreiraš i inicijalizuješ novu instancu struct-a (Block u ovom slučaju). <br> > `pub` znači da je metod javno dostupan, tj. možeš ga pozvati iz drugog modula ili fajla.

Parametri metode:

- id: u64 → ID bloka
- previous_hash: String → hash prethodnog bloka (za vezu u blockchain-u)
- data: String → podaci u bloku (npr. transakcije)
- nonce: u64 → broj koji se koristi za “mining” ili dokaz rada

Self znači da funkcija vraća instancu strukture u kojoj je metod definisan (Block)

<b>Šta se dešava unutra?</b>

```
let mut block = Self {
    id,
    timestamp: Utc::now().timestamp(),
    previous_hash,
    data,
    nonce,
    hash: String::new(),
};
```

> Kreira se privremeni mutable (promenljivi) blok sa svim poljima. <br>
> timestamp: Utc::now().timestamp() postavlja trenutno vreme. <br>
> hash: String::new() kreira prazan string, jer hash još ne znamo.

---

## Zasto smo definisali parametre u new metodi i kod `let mut block = Self`

### 1. Definicija parametara u new metodu

```
pub fn new(
    id: u64,
    previous_hash: String,
    data: String,
    nonce: u64,
) -> Self {

```

> Ovim definišemo ulazne podatke koji se šalju kada neko želi da napravi novi blok.
> id: u64 → ID bloka koji se prosleđuje
> previous_hash: String → hash prethodnog bloka?
> data: String → sadržaj bloka
> nonce: u64 → broj koji se koristi za “mining”
> <b>Ovi parametri su lokalne promenljive unutar funkcije new</b>

To znači da unutar ove funkcije sad imaš promenljive id, previous_hash, data, nonce koje drži vrednosti koje je pozivalac prosledio.

### 2. Inicijalizacija struct-a

```
let mut block = Self {
    id,
    timestamp: Utc::now().timestamp(),
    previous_hash,
    data,
    nonce,
    hash: String::new(),
};
```

> Self ovde znači Block struct (tako se u Rust-u piše unutar impl). <br>
> Dakle, pravimo novu instancu Block i popunjavamo polja struct-a (id, timestamp, previous_hash, data, nonce, hash). <br>
> Kada pišeš ovako: <br>

```
id,
previous_hash,
data,
nonce,
```

> to je skraćeni Rust način za:

```
id: id,
previous_hash: previous_hash,
data: data,
nonce: nonce,
```

Prva strana id: je ime polja u struct-u, <br>
Druga strana id je lokalna promenljiva iz funkcije (parametar).

### Zaključak

1. Parametri u new → ulazne vrednosti koje daje pozivalac.
2. Polja u Self { ... } → stvarna polja Block struct-a koja se inicijalizuju.
3. Skraćeni zapis id, previous_hash, ... je samo syntactic sugar za id: id, previous_hash: previous_hash, ....

#### Zasto ne mozes kod refaktorisanog koda raditi kao u primeru gde je sve u main.rs?

Problem:

- block još ne postoji dok pokušavaš da pozoveš calculate_hash na njemu.
- Rust ne dopušta “self-reference” pri inicijalizaciji strukture.

Zato je potrebno:

- Napraviti blok sa privremenim praznim hash-om (String::new()),
- Izračunati hash metodom,
- Postaviti hash polje,
- Vratiti kompletan blok.

To je razlog zašto je new metod neophodan u ovom slučaju.

## main.rs

`:: se koristi za funkcije i asocirane metode koje nisu vezane za instancu <br>`
Primer: konstruktori, konstante, statičke funkcije

```
let bc = Blockchain::new(2); // konstruktorska funkcija
```

`. se koristi za pozivanje metoda na instanci`

```
bc.add_block("prvi blok".to_string()); // metoda koja menja blockchain
```

---

## Tumacenje koda

```
self.blocks.push(new_block);
```

Ovo je klasično Rust pristupanje poljima struct-a kroz instancu

self = instanca trenutnog objekta (ovde Blockchain) <br>
Kada pišeš metodu:

<b>1. Sta je self </b>

```
pub fn add_block(&mut self, data: String) { ... }
```

- self = blockchain na kojem pozivaš ovu funkciju
- &mut self znači da možeš menjati taj blockchain

<b>2. Sta je self.blocks </b>
blocks je polje u Blockchain struct-u
Dakle:

- self.blocks = vektor svih blokova u ovom blockchain-u
- self.blocks je tipa Vec<Block>

<b>Šta radi .push(new_block)?</b>
Vec<Block> ima metodu push() koja dodaje element na kraj vektora <br>
Dakle, uzima blok koji si napravio (new_block) i dodaje ga na kraj blockchain-a
