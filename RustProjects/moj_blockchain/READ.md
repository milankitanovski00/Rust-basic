# Moj prvi blockchain

```
use chrono::{DateTime, NaiveDate, NaiveDateTime};
use sha2::digest::block_buffer;
use sha2::{Digest, Sha256};
use std::arch::x86_64::_MM_EXCEPT_INEXACT;
use std::fmt::format;
use std::ops::Index;
use std::{fmt, result, string};
use std::time::{SystemTime, UNIX_EPOCH};
use std::thread;
use std::time::Duration;
```

use sha::{Digest, Sha256};

sha je biblioteka za heširanje.<br>
Sha256 je algoritam koji pravi 256-bitni heš. <br>
Digest je trait (slično interfejsu) koji daje metode kao update() i finalize() da računaš heš. <br>
Ukratko: ovo ti omogućava da praviš heš blokova u blockchain-u. <br>

use std::fmt;

fmt je standardna biblioteka za formatiranje i prikazivanje podataka. <br>
Koristi se kada želiš da implementiraš Display ili Debug trait, tj. kako da lepo ispišeš podatke (npr. blok ili heš). <br>

use std::time::{SystemTime, UNIX_EPOCH};

SystemTime daje trenutni datum i vreme. <br>
UNIX_EPOCH je referentna tačka (1. januar 1970.) od koje meriš vreme. <br>
Ovo ti treba da dodaš timestamp u blok u blockchain-u. <br>

use std::thread;

Omogućava ti da koristiš thread-ove, tj. paralelno izvršavanje koda. <br>
Može ti biti korisno ako simuliraš rudarenje ili neku asinhronu operaciju. <br>

use std::time::Duration;

Duration predstavlja vreme trajanja (sekunde, milisekunde, nanosekunde). <br>
Obično se koristi sa thread::sleep(Duration::from_secs(n)) da pauziraš program na n sekundi (npr. simulacija rudarenja). <br>

## Napomena: u Cargo.toml je dodato ispod [dependencies]:

```
sha2 = "0.10.6"
chrono = "0.4.35"
```

Ovo su dependency-ja (zavisnosti) koje tvoj projekat koristi. <br>
sha2 → biblioteka za SHA-2 hash funkcije (npr. SHA-256) <br>
chrono → biblioteka za rad sa datumom i vremenom <br>

Napomena: Mislim da si morao ovo rucno generisati (a moze i automatski) - ja sam bar rucno (nisam insstalirao okruzenje za VSC)

---

```
const DIFFICULTY: usize = 2;
```

Ova linija definiše konstantu DIFFICULTY koja određuje koliko je teško rudarenje novog bloka u blockchain simulaciji; veća vrednost znači da rudarenje zahteva više pokušaja da se nađe validan heš. <br>
U blockchain-u svaki novi blok sadrži heš prethodnog bloka u svojoj strukturi. Hesh se traži jer je osnovni mehanizam sigurnosti i verifikacije u blockchain-u.<br>
Rudarenje znači pronaći heš bloka koji zadovoljava određeni uslov (npr. počinje sa određenim brojem nula — to je DIFFICULTY <br>

## Ovo je Rust struct koja definiše blok u blockchain-u:

```
struct Block {
index: u32,                 //index bloka u lancu
previous_hash: String,      //hash predhodnog bloka
timestamp: u64,             //vremenska oznaka za kreiranje bloka
data : String,
nonce: u64,                //nonce se koristi za rudarenje
hash: String,               //trenutni hash bloka
}
```

Svaka promenljiva u strukturi je polje bloka. <br>
Struktura samo čuva podatke, ali ne zna kako da ih koristi. <br>

## struct samo definiše podatke.

Ako želiš da blok može da računa svoj heš, rudari, ili pravi novi blok, treba ti impl Block gde pišeš metode (funkcije) za blok.

```
impl Block{
    fn new(index: u32, previous_hash: String, data: String) -> Block{
        let timestamp: u64 = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs();
        Block { index,
             previous_hash,
             timestamp,
             data,
             nonce: 0,
            hash: String::new(),
        }
    }
```

### Objasnjenje koda

#### Šta radi ova funkcija new

```
fn new(index: u32, previous_hash: String, data: String) -> Block
```

Kreira novi blok sa zadatim podacima:

1. index → redni broj bloka (u32 je tip podatka za celobrojne vrednosti bez znaka, 32-bita)
2. previous_hash → heš prethodnog bloka
3. data → sadržaj bloka (npr. transakcije)

Vraća instancu Block.

#### Vremenska oznaka (timestamp)

```
let timestamp: u64 = SystemTime::now()
.duration_since(UNIX_EPOCH)
.expect("Time went backwards")
.as_secs();
```

Uzima trenutno vreme u sekundama od Unix epohe (1.1.1970). <br>
Ako je vreme „unazad“ (praktično ne može, ali Rust traži proveru), panikuje sa "Time went backwards". <br>
To je standardni način da se blokovima dodeli vremenska oznaka kreiranja. <br>  
U Rust-u, .as_secs() se koristi da konvertuje trajanje (Duration) u sekunde kao u64

#### Inicijalizacija polja bloka

```
Block {
    index,
    previous_hash,
    timestamp,
    data,
    nonce: 0,
    hash: String::new(),
}
```

nonce: 0 → početna vrednost za rudarenje (traženje validnog heša), Počinje obično od 0 zatim se povećava (nonce += 1) dok se ne pronađe validan heš za blok. Nonce se menja dok se ne pronađe heš koji zadovoljava DIFFICULTY, pa veća težina (DIFFICULTY) znači više pokušaja (nonce) da se blok uspešno izrudari. -> DIFFICULTY - hash pocinje sa 2 nule <br>
hash: String::new() → heš će se kasnije izračunati metodom rudarenja <br>

Napomena: Rust omogućava skraćeni zapis index, previous_hash, data umesto index: index, ....

Struktura Block samo čuva podatke, ali funkcija new je konstruktor koji pravi blok sa osnovnim poljima. Bez ove funkcije, svaki put bi morao da pišeš:

```
Block {
    index: 1,
    previous_hash: String::from("0"),
    timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
    data: String::from("neki podaci"),
    nonce: 0,
    hash: String::new(),
}
```

new pojednostavljuje kreiranje bloka i čini kod preglednijim.

## Funkcija calculate_hash

```
 fn calculate_hash(&mut self) -> String {
        let data: String = format!(  //ovde formatiramo string sa: indeks, prethodni heš, vremenska oznaka, podaci i nonce vrednoscu
            "{}{}{}{}{}",           //U suštini, ono što radimo jeste da u promenljivoj data spajamo (konkateniramo) atribute bloka u jedan jedinstveni string.
            self.index,             //To je cela ideja — spajamo indeks, prethodni heš i tako dalje u jedan string.
            &self.previous_hash,
            self.timestamp,
            &self.data,
            self.nonce
        );

        let mut hasher = Sha256::new(); //pravimo sha256 hasher i u donjoj liniji:
        hasher.update(data.as_bytes());                                         //ažuriraćemo ga podacima bloka
        let result = hasher.finalize();

        let hash_str: String = format!("{:x}", result); //Rezultat će zatim biti formatiran unutar tog hešera i na kraju ćemo ga vratiti.
        hash_str //Kao što vidite, poslednja linija nema tačku-zarez, jer smo ranije rekli da Rust vraća vrednost poslednje linije.
    }
```

### Objasnjenje koda

```
fn calculate_hash(&mut self) -> String
```

Funkcija radi:

1. Računa heš trenutnog bloka koristeći SHA-256. <br>
2. Vraća rezultat kao string u heksadecimalnom formatu. <br>

self → predstavlja trenutni blok (instancu Block)<br>
&self → referenca na blok (ne kopira ceo blok)<br>
&mut self → mutable referenca, znači da funkcija može menjati polja bloka unutar sebe<br>

Kako znamo da self znaci blok? <br>
U metodama unutar impl bloka, self predstavlja instancu tipa za koji je impl definisan.

```
-> String
```

Ovo znaci: String je povratna vrednost

#### 1.Spajanje atributa bloka u jedan string:

```
let data: String = format!("{}{}{}{}{}", self.index, &self.previous_hash, self.timestamp, &self.data, self.nonce);
```

Uzima:

1. index → redni broj bloka
2. previous_hash → heš prethodnog bloka
3. timestamp → vreme kreiranja
4. data → sadržaj bloka
5. nonce → broj pokušaja

Svi se kombinuju u jedan jedinstveni string (data) koji će biti heširan.

#### 2. Pravljenje SHA-256 hešera i ažuriranje sa podacima:

```
let mut hasher = Sha256::new();
hasher.update(data.as_bytes());
```

data.as_bytes() pretvara string u bajtove <br>
hasher.update(...) priprema podatke za heširanje <br>

#### 3. Dobijanje heša i formatiranje:

```
let result = hasher.finalize();
let hash_str: String = format!("{:x}", result);
```

finalize() vraća niz bajtova (heš) <br>
format!("{:x}", result) pretvara bajtove u heksadecimalni string, npr. "00af3c..."

#### 4. Vraćanje heša:

```
hash_str
```

Rust automatski vraća poslednju liniju ako nema tačku-zarez.

#### Suština

Funkcija uzima sve podatke iz bloka, spaja ih u string i računa SHA-256 heš. <br>
Taj heš kasnije služi za: <br>

1. verifikaciju bloka
2. povezivanje sa sledećim blokom
3. proveru validnosti rudarenja (DIFFICULTY)

---

#### Pitanja

1. Kod format!("{}{}{}{}{}", ... svaki {} je placeholder za vrednost koju prosledjujemo u format. Redosled je bitan! Rezultat je jedan string koji spaja sve polja: "1abcdef123456789012345data0"
2. Pretvaranje u bajtove. data.as_bytes() pretvara string u niz bajtova ([u8]), jer SHA-256 radi samo sa bajtovima, ne sa stringovima.
3. Zašto se koristi update?
   - update() dodaje podatke u unutrašnji buffer hashera.
   - Dakle, update() priprema podatke za heširanje i dodaje ih u hasher internu memoriju.
4. Šta radi finalize()?
   - finalize() izračunava konačni hash na osnovu svih podataka koji su prosleđeni preko update().
   - hasher nakon finalize() više ne može se koristiti, tj. hash je završen.
   - Ne možeš samo napisati let result = hasher, jer hasher je objekat koji čuva stanje i nije sam heš.
   - result je niz bajtova [u8; 32] (SHA-256 uvek vraća 32 bajta).
5. Šta znači :x u {:x}
   - :x → heksadecimalni zapis
   - Svaki bajt iz result se pretvara u dve heksadecimalne cifre (0-9 i a-f)
   - Bez :x, format bi bio debug format ili bajtovi, što nije lepo za čitanje.

---

## metoda mine_block_with_visual_effects

Poslednja metoda u implementaciji bloka je mine_block sa vizuelnim efektima, i ona radi upravo to — rudari blok sa vizuelnim efektima

```
fn mine_block_with_visual_effects(&mut self){
        let mut iterations: i32 = 0;                                                        //Prvo inicijalizujemo brojač iteracija tako što
        loop {                                                                              //Zatim koristimo loop:
            self.hash = self.calculate_hash();                                              //izračunavamo heš bloka,
            iterations += 1;                                                                //uvećavamo brojač iteracija,
        if !self.hash.is_empty() && &self.hash[..DIFFICULTY] == "00".repeat(DIFFICULTY){    //proveravamo da li heš ispunjava uslov težine (difficulty),
            println!("Block mined: {}", self.index);                                        //štampamo poruku koja označava uspešno rudarenje bloka i
            break;                                                                          //na kraju izlazimo iz petlje.
        }
        if iterations > 100 {                                                               //Ako broj iteracija pređe određenu granicu,
            print!("Mining in progress...");
            thread::sleep( Duration::from_millis(3000));                                    //štampaćemo izračunati heš i napraviti pauzu radi vizuelnog efekta.
            println!("Calculated hash: {}", self.hash);
            break;
        }
        self.nonce += 1;                                                                    //uvećamo nonce za sledeću iteraciju.
        }
    }
```

### Objasnjenje koda

#### 1. Funkcija i njen cilj

```
fn mine_block_with_visual_effects(&mut self)
```

Ovo je metoda za rudarenje bloka. <br>
&mut self → metoda može menjati polja bloka (nonce i hash). <br>
Vizuelni efekti se postižu printanjem i pauzom (sleep) tokom procesa. <br>

Cilj: pronaći hash koji zadovoljava DIFFICULTY ("00" ponovljeno DIFFICULTY puta).

#### 2. Inicijalizacija brojača iteracija

```
let mut iterations: i32 = 0;
```

Brojač pokušaja (iterations) za vizuelni efekat i kontrolu ispisa. <br>
mut jer ćemo ga menjati u petlji.

#### 3. Beskonačna petlja loop

```
loop {
    ...
}
```

Petlja se vrti dok hash ne zadovolji DIFFICULTY ili dok ne dođe do vizuelnog limita (iterations > 100).

#### 4. Računanje heša (U infinity loop-u)

```
self.hash = self.calculate_hash();
iterations += 1;
```

Svaka iteracija računa novi hash sa trenutnim nonce vrednostima.<br>
Brojač iteracija se uvećava.

#### 5. Provera DIFFICULTY

```
if !self.hash.is_empty() && &self.hash[..DIFFICULTY] == "00".repeat(DIFFICULTY) {
    println!("Block mined: {}", self.index);
    break;
}
```

!self.hash.is_empty() → proverava da hash nije prazan (sigurnosna provera). <br>
&self.hash[..DIFFICULTY] → uzima prvih DIFFICULTY karaktera hash-a. <br>
"00".repeat(DIFFICULTY) → string koji mora odgovarati (npr. "00" ako DIFFICULTY=1, "0000" ako 2 <br>
Ako je hash validan → štampa poruku i izlazi iz petlje. <br>

šta znači ..?

- U Rust-u a..b ili ..b je range (opseg) za sečenje niza ili stringa.
- &self.hash[..DIFFICULTY] znači: uzmi prve DIFFICULTY karaktera stringa self.hash.

šta radi repeat?

- repeat(n) pravi novi string tako što ponavlja originalni string n puta.
- "00".repeat(2) → "0000" (dve kopije "00" spojene zajedno)
- "00".repeat(3) → "000000"

Ako je DIFFICULTY = 2 → traži "0000" na početku hasha. Tako se definiše težina rudarenja: više nula → teže rudarenje.

#### 6. Vizuelni efekat

```
if iterations > 100 {
    print!("Mining in progress...");
    thread::sleep(Duration::from_millis(3000));
    println!("Calculated hash: {}", self.hash);
    break;
}
```

Ako rudarenje traje previše iteracija, pravi se pauza od 3 sekunde (sleep) i ispisuje se trenutni hash <br>
Ovo daje korisniku vizuelni osećaj da se rudari, ali zapravo zaustavlja petlju.

#### 7. Povećavanje nonce

```
Povećavanje nonce
```

Povećava nonce da bi sledeći hash bio drugačiji. <br>
Bitno za proof-of-work: hash se menja samo promenom nonce.

---

#### Sažetak toka

1. Petlja počinje i brojač iteracija je 0.
2. Izračunava se hash sa trenutnim nonce.
3. Ako hash zadovoljava DIFFICULTY → blok je uspešno izrudaren → izlaz iz petlje.
4. Ako iteracije > 100 → print + sleep za vizuelni efekat → izlaz.
5. Ako ništa od ovoga → povećava nonce i ponavlja pet

Vizuelna analogija:

```
[nonce=0] -> hash="1a2b..." -> nije dovoljno "00..." -> nonce+=1
[nonce=1] -> hash="00fa..." -> zadovoljava DIFFICULTY -> block mined!
```

---

#### Sada želimo da implementiramo formatiranje strukture bloka kako bismo omogućili ispis. Da bismo to uradili, jednostavno ćemo napraviti funkciju za formatiranje, koja radi upravo to — formatira izlaz. <br> Dakle, da budemo jasni, ovo je implementacija Display trait-a za strukturu Block. Ova implementacija definiše kako instanca bloka treba da izgleda kada se ispisuje.

Trait u Rust-u je skup metoda koje tip može da implementira, slično interfejsu u drugim jezicima, i definiše ponašanje tipa.

```
impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {          //Ovo je funkcija fmt: kao prvi parametar prima referencu na self, a f je mutabilna referenca na                                                                                        formatter, i funkcija vraća formatirani rezultat.
        let datetime:NaiveDateTime = chrono::NaiveDateTime::from_timestamp(self.timestamp as i64,  0);                          //u ovoj naredbi jednostavno konvertujemo
        write!(                                                                                     //Na kraju koristimo write! makro da formatiramo informacije o bloku.
            f,                              //On upisuje indeks bloka, podatke i vremensku oznaku u formatter f, a placeholders se zamenjuju odgovarajućim vrednostima:
            "Block {}: {} at {}",                                           //self.index, self.data i date_time.
            self.index, self.data, datetime
        )
    }
}
```

### Objasnjenje koda

#### 1. Šta radi ovaj kod

```
impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        ...
    }
}
```

Ovde implementiraš Display trait za Block. <br>
Display definiše kako će blok izgledati kada ga ispišeš pomoću println! ili format!. <br>
fmt(&self, f: &mut fmt::Formatter) -> fmt::Result je obavezna funkcija za Display:

- self → instanca bloka
- f → formatter u koji upisuješ string
- fmt::Result → rezultat formatiranja

#### 2. Pretvaranje timestamp-a u datum

```
let datetime: NaiveDateTime = chrono::NaiveDateTime::from_timestamp(self.timestamp as i64, 0);
```

self.timestamp → Unix timestamp (vremenska oznaka) u sekundama <br>
from_timestamp(..., 0) → pretvara u NaiveDateTime, tj. čitljiv datum i vreme <br>

```
chrono::NaiveDateTime::from_timestamp(timestamp, nsecs)
```

je funkcija koja pretvara Unix timestamp u NaiveDateTime, tj. čitljiv datum i vreme bez vremenske zone.

Objašnjenje parametara

1. timestamp: i64 → broj sekundi od Unix epohe (1. januar 1970.)
2. nsecs: u32 → broj nanosekundi dodatnih posle sekundi (može biti 0 ako ne želiš preciznost manju od sekunde)

U Rust-u, :: znači pristup članu modula, strukture, funkcije ili konstante unutar namespace-a:

```
chrono::NaiveDateTime  // pristup strukturi NaiveDateTime unutar modula chrono
String::new()          // poziv funkcije new() strukture String
```

Dakle, `::` se koristi za navigaciju kroz module i tipove, slično tački . u drugim jezicima, ali za statike, tipove i funkcije, ne za instance.

#### 3. Formatiranje izlaza sa write!

```
write!(
    f,
    "Block {}: {} at {}",
    self.index, self.data, datetime
)
```

write! upisuje string u formatter f <br>
{} su placeholders:

1. Prvi {} → self.index
2. Drugi {} → self.data
3. Treći {} → datetime

Na kraju funkcija vraća `fmt::Result` → obavezan deo `Display`.

#### Zašto ovo radimo

Bez ove implementacije, println!("{}", block) ne bi radio, jer Rust ne zna kako da prikaže blok. <br>
Sada možeš lepo ispisivati blokove:

```
println!("{}", my_block);
// Output: Block 1: Some data at 2026-01-09 13:25:01
```

---

<b>Napomena:</b>
`!` označava makro, a ne običnu funkciju

Funkcija:

```
fn add(a: i32, b: i32) -> i32 {
    a + b
}
```

Poziva se sa zagradama, vraća vrednost. <br>
Poziva se sa zagradama, vraća vrednost. <br>

Makro:

```
println!("Hello {}", name);
write!(f, "Block {}", index);
```

Makro može raditi sa varijabilnim brojem argumenata. <br>
Može parsirati string sa {} placeholder-ima i generisati kod za formatiranje u kompajlerskom trenutku. <br>
Kompajler “proširi” makro u više instrukcija pre nego što se kod izvrši <br>

<b>Zašto write! mora sa !:</b>
write! ne može biti obična funkcija jer prima formatter + varijabilan string sa {}. <br>
Makro write! generiše odgovarajući kod koji poziva f.write_fmt(...) za te argumente. <br>

---

<b>Sada možemo da pređemo na kreiranje strukture blockchain-a. </b>

Počinjemo sa ključnom rečju struct Blockchain, i unutar vitičastih zagrada imamo vektor koji čuva blokove u lancu.

```
struct Blockchain {
chain: Vec<Block>,
}
```

`chain` → ime polja (field) unutar strukture Blockchain. <br>
`Vec<Block>` → tip polja, znači vektor blokova.  
Zašto nema let?

<b>Zašto nema let?</b> <br>

- let se koristi za lokalne promenljive unutar funkcija ili blokova koda.
- Kada definišeš polja unutar strukture, samo navodiš ime polja i njegov tip, bez let.

Šta je `Vec<Block>`?

- Vec<T> u Rust-u je dinamički niz (vector).
- Može rasti i smanjivati se u runtime-u.
- Vec<Block> znači da čuvamo niz blokova, i možemo dodavati nove blokove kako lanac raste.

`Vec<Block>` omogućava:

```
let mut blockchain = Blockchain { chain: Vec::new() };
blockchain.chain.push(new_block);  // dodavanje novog bloka
```

---

Zatim pišemo implementaciju za blockchain.

## Implementacija Blockchaina

### Konstruktor new()

```
impl Blockchain {
    fn new() -> Blockchain {                                //Imaćemo konstruktor za kreiranje novog blockchain-a sa Genesis blokom.
        let genesis_block: Block = Block::new(0,            //Inicijalizujemo lanac sa Genesis blokom
        String::new(), String::from("Genesis Block"));
        Blockchain {
            chain: vec![genesis_block],
        }
    }

...
```

Šta radi:

1. Kreira Genesis blok (prvi blok u lancu):

- index = 0
- previous_hash = "" (prazan string, jer nema prethodnog bloka)
- data = "Genesis Block"

2. Inicijalizuje Blockchain sa poljem chain koje je vektor i odmah sadrži Genesis blok.

`Zašto vec![genesis_block]?`

- vec![...] pravi vektor sa jednim elementom, u ovom slučaju Genesis blok.

U Rust-u vec! sa ! znači da je makro, a ne obična funkcija. Makro je `“instrukcija kompajleru”` koja generiše kod u vreme kompajliranja <br>
Rust dolazi sa ugrađenim makroima kao što su `println!`, `vec!`, `write!` – oni ponašaju se kao funkcije, ali mogu da rade stvari koje funkcije ne mogu, npr.:<br>

- varijabilan broj argumenata
- generisanje više linija koda
- specijalna sintaksa ({} za placeholder, [] za inicijalizaciju)

Makro je ugrađena Rust `“funkcija”` koja generiše kod pre izvršavanja i može raditi fleksibilnije stvari od običnih funkcija.

---

Zatim su nam potrebne još dve funkcije: jedna za dodavanje novog bloka u blockchain i druga za dobijanje ukupnog broja blokova u lancu.

### Funkcija add_block

```
fn add_block(&mut self, mut new_block: Block) {
        let previous_hash: String = self.chain.last().unwrap().hash.clone();            //uzimamo heš prethodnog bloka, postavljamo taj heš kao prethodni heš novog bloka
        new_block.previous_hash = previous_hash;
        new_block.mine_block_with_visual_effects();                                     //rudarenje (mine) novog bloka i
        self.chain.push(new_block);                                                     //dodajemo blok u lanac
    }
```

#### 1. Parametri i &mut self

`&mut self` → metoda menja instancu blockchain-a, tj. dodaje blokove u lanac. <br>
`mut new_block: Block` → blok koji dodajemo može da se menja unutar funkcije (npr. da mu postavimo previous_hash i da ga rudari).

#### 2. Uzmi heš prethodnog bloka

```
let previous_hash: String = self.chain.last().unwrap().hash.clone();
```

`self.chain.last()` → uzima poslednji blok u lancu <br>
`.unwrap()` → pretpostavljamo da lanac nije prazan (.unwrap() uzima vrednost iz Option tipa i panic-uje ako je None, dakle u ovom slučaju uzimamo poslednji blok jer pretpostavljamo da lanac nije prazan.)<br>
`.hash.clone()` → kopira heš poslednjeg bloka u novu promenljivu <br>

Zbog čega? Novi blok mora da zna prethodni heš da bi lanac bio povezan

#### 3. Postavljanje prethodnog heša novom bloku

```
new_block.previous_hash = previous_hash;
```

Novi blok sada “zna” koji blok prethodi njemu <br>
Ovo je ključni deo blockchain-a: svaki blok zavisi od heša prethodnog.

#### 4. Rudarenje novog bloka

```
new_block.mine_block_with_visual_effects();
```

Pozivamo metodu koja računa hash tako da zadovoljava difficulty (proof-of-work) <br>
Vizuelni efekti (printanje, sleep) su samo za korisnika, stvarni hash se računa u calculate_hash().

### Funkcija get_total_blocks

```
fn get_total_blocks(&self) -> usize {               //vraća ukupan broj blokova u blockchain-u.
    self.chain.len()
}
```

Ova funkcija `get_total_blocks` jednostavno vraća broj blokova u lancu tako što poziva `len()` na vektoru chain

---

Time smo završili sve vezano za blockchain i blok — od struktura do implementacije. Sada možemo da krenemo sa pisanjem koda unutar main funkcije. <br>
Došli smo do glavne funkcije za simulaciju blockchain-a.
