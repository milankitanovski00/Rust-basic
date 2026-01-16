use chrono::{DateTime, NaiveDate, NaiveDateTime};
use sha2::digest::block_buffer;
//Import the necessary dependencies
use sha2::{Digest, Sha256};
use std::arch::x86_64::_MM_EXCEPT_INEXACT;
use std::fmt::format;
use std::ops::Index;
use std::{fmt, result, string};
use std::time::{SystemTime, UNIX_EPOCH};
use std::thread;
use std::time::Duration;

//Define difficulty of the mining
const DIFFICULTY: usize = 2;  //težinu rudarenja-proces dodavanja novog bloka podrazumeva rešavanje

//Define the structure of a block in the blockchain
//Struct and implementation
struct Block {
    index: u32,                     //index bloka u lancu
    previous_hash: String,          //hash predhodnog bloka
    timestamp: u64,                 //vremenska oznaka za kreiranje bloka
    data : String,                  
    nonce: u64,                     //nonce se koristi za rudarenje
    hash: String,                   //trenutni hash bloka
}

impl Block{
    fn new(index: u32, previous_hash: String, data: String) -> Block{       //konstruktor za kreiranje bloka, ulazi: index i prethodni heš i podac, dok je rezultat blok
        let timestamp: u64 = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs();    //želimo da dobijemo trenutnu vremensku oznaku u sekundama, jer koristimo Unix Epoch.
        Block { index,
                previous_hash, 
                timestamp, 
                data, 
                nonce: 0, 
                hash: String::new(), 
        }           //trebamo postaviti indeks, prethodni heš, vremensku oznaku i podatke dok cemo nonce i hash ćemo inicijalizovati.
    }

    //sada nam je potrebno da kreiramo metodu za izračunavanje heša bloka.
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

    //Poslednja metoda u implementaciji bloka je mine_block sa vizuelnim efektima, i ona radi upravo to — rudari blok sa vizuelnim efektima
    fn mine_block_with_visual_effects(&mut self){
        let mut iterations: i32 = 0; //Prvo inicijalizujemo brojač iteracija tako što
        loop {                                  //Zatim koristimo loop:
            self.hash = self.calculate_hash();  //izračunavamo heš bloka,
            iterations += 1;                    //uvećavamo brojač iteracija,
        if !self.hash.is_empty() && &self.hash[..DIFFICULTY] == "00".repeat(DIFFICULTY){    //proveravamo da li heš ispunjava uslov težine (difficulty),
            println!("Block mined: {}", self.index);            //štampamo poruku koja označava uspešno rudarenje bloka i
            break;                                          //na kraju izlazimo iz petlje.
        }
        if iterations > 100 {       //Ako broj iteracija pređe određenu granicu,
            print!("Mining in progress...");           
            thread::sleep( Duration::from_millis(3000));             //štampaćemo izračunati heš i napraviti pauzu radi vizuelnog efekta.
            println!("Calculated hash: {}", self.hash);
            break;
        }
        self.nonce += 1; //uvećamo nonce za sledeću iteraciju.
        }
    }
}

//Sada želimo da implementiramo formatiranje strukture bloka kako bismo omogućili ispis.
//Da bismo to uradili, jednostavno ćemo napraviti funkciju za formatiranje, koja radi upravo to — formatira izlaz.
//Dakle, da budemo jasni, ovo je implementacija Display trait-a za strukturu Block.
//Ova implementacija definiše kako instanca bloka treba da izgleda kada se ispisuje.

impl fmt::Display for Block {           
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {      //Ovo je funkcija fmt: kao prvi parametar prima referencu na self, a f je mutabilna referenca na formatter, i funkcija vraća formatirani rezultat.
        let datetime:NaiveDateTime = chrono::NaiveDateTime::from_timestamp(self.timestamp as i64,  0); //u ovoj naredbi jednostavno konvertujemo
        write!( //Na kraju koristimo write! makro da formatiramo informacije o bloku.
            f,                      //On upisuje indeks bloka, podatke i vremensku oznaku u formatter f, a placeholders se zamenjuju odgovarajućim vrednostima:
            "Block {}: {} at {}",       //self.index, self.data i date_time.
            self.index, self.data, datetime
        )
    }
}
//Time smo završili sa blokom.

//Sada možemo da pređemo na kreiranje strukture blockchain-a. 
//Počinjemo sa ključnom rečju struct Blockchain, i unutar vitičastih zagrada imamo vektor koji čuva blokove u lancu.
struct  Blockchain {
    chain: Vec<Block>,
}

//Zatim pišemo implementaciju za blockchain.
impl Blockchain {
    fn new() -> Blockchain {    //Imaćemo konstruktor za kreiranje novog blockchain-a sa Genesis blokom.
        let genesis_block: Block = Block::new(0, //Inicijalizujemo lanac sa Genesis blokom
        String::new(), String::from("Genesis Block")); 
        Blockchain {
            chain: vec![genesis_block],
        }
    }

    // zatim su nam potrebne još dve funkcije:
    // jedna za dodavanje novog bloka u blockchain i
    // druga za dobijanje ukupnog broja blokova u lancu.

    //Funkcija add_block u suštini dodaje novi blok u blockchain.
    //Da bismo to implementirali, uzimamo heš prethodnog bloka, postavljamo taj heš kao prethodni heš novog bloka
    fn add_block(&mut self, mut new_block: Block) {
        let previous_hash: String = self.chain.last().unwrap().hash.clone(); //uzimamo heš prethodnog bloka, postavljamo taj heš kao prethodni heš novog bloka
        new_block.previous_hash = previous_hash;
        new_block.mine_block_with_visual_effects(); //rudarenje (mine) novog bloka i
        self.chain.push(new_block); //dodajemo blok u lanac
    }

    fn get_total_blocks(&self) -> usize {  //vraća ukupan broj blokova u blockchain-u.
        self.chain.len()
    }
}


//Time smo završili sve vezano za blockchain i blok — od struktura do implementacije.
//Sada možemo da krenemo sa pisanjem koda unutar main funkcije.

//Došli smo do glavne funkcije za simulaciju blockchain-a.
fn main() {
    println!("Welcome to my first coin simulator"); //Prva println! poruka je poruka dobrodošlice.

    println!("Enter your miner name: "); //Zatim tražimo od korisnika da unese svoje ime,

    let mut miner_name: String = String::new();

    std::io::stdin().read_line(&mut miner_name).expect("Failed to read input"); //sistem čita korisnikov unos,
    
    miner_name = miner_name.trim().to_string(); //a zatim imamo miner_name, koji je jednak miner_name.trim().to_string(),što uklanja razmake sa početka i kraja unosa.
    
    let trader_names: Vec<&str> = vec!["Bob", "Linda"]; //Sledeće, inicijalizujemo listu izmišljenih imena, trgovaca: Bob, Linda, John, Omar, Eve, Lana, Grace i Jero.
                                                        //To je dva imena, plus vaše ime kao trece, kako bismo imali tri blokova u blockchain-u.
    let mut bekcoin: Blockchain = Blockchain::new();    //Zatim inicijalizujemo novi blockchain sa let mut bitcoin = Blockchain::new()

    println!("\n Let's sturt mining and simulating transactions!\n"); //Ispisujemo poruku korisniku da započinjemo rudarenje i simulaciju transakcija

    let mut sender: String = miner_name.clone(); //Zatim pravimo string promenljivu sender koja je jednaka miner_name.clone().
                                            //U Rust-u promenljive imaju semantiku vlasništva. Ukratko, promenljive predstavljaju vlasništvo nad podacima koje sadrže. Kada dodelite vrednost promenljivoj,ta promenljiva postaje vlasnik te vrednosti.
                                            //Vlasništvo obezbeđuje sigurnost memorije i sprečava data race situacije, tako što nameće stroga pravila o tome kako se podacima može pristupati i kako se mogu menjati.
                                            //Kada kažemo let mut sender = miner_name.clone(), prvi deo deklariše novu mutabilnu promenljivu sender,a mut znači da se njena vrednost može menjati.
                                            //Drugi deo, miner_name.clone(), poziva metodu clone nad stringom. Ta metoda pravi potpuno novu instancu stringa, identičnu originalu, sa sopstvenom memorijom, nezavisnu od originalnog stringa.

    for i in 0..trader_names.len() { //Zatim prolazimo kroz imena trgovaca.
        println!("Mining block {}...", i+1);    //za svako ime ispisujemo odgovarajuću poruku.
        let recipient: String = if i < trader_names.len() - 1 {     //Zatim određujemo primaoca transakcije:
            trader_names[i + 1].to_string()     //ako je i manje od trader_names.len() - 1, onda je primalac trader_names[i + 1] odnosno prelazimo na sledeće ime,, a u suprotnom je primalac miner_name što znači da se poslednja transakcija vraća rudaru.
        } else {                                //Ako ste primetili, počinjemo sa imenom rudara (vašim imenom) i završavamo ponovo sa vašim imenom.
            miner_name.clone()  //miner_name je string. Sve ovo sam objasnio da bismo došli do metode clone. clone je metoda koju obezbeđuje tip String u Rust-u i ona u suštini pravi novu instancu stringa koja je tačna kopija originalnog stringa.
        };                      //Ovo je genijalno jer ta nova instanca ima sopstvenu alokaciju memorije i potpuno je nezavisna od originalne.

        let transaction: String = format!("{} sent to {}", sender, recipient); //Zatim kreiram poruku transakcije, 

        let new_block: Block = Block::new((i+1) as u32, String::new(), transaction.clone()); //onda novi blok sa tom transakcijom i

        bekcoin.add_block(new_block);   //dodajemo izrudaren blok u blockchain,

        println!("Transaction: {}", transaction); //dok istovremeno ispisujemo poruku o transakciji.

        sender = recipient; //Nakon toga ažuriramo pošiljaoca za sledeću transakciju.

        println!();   //Ovde jednostavno ispisujemo novi red radi razmaka.
    }
    let total_blocks: usize = bekcoin.get_total_blocks(); //Što se tiče ukupnog broja blokova, računamo koliko je blokova dodato u blockchain.

    print!("Total blocks added to the blockchain: {}", total_blocks);   //Zatim ih ispisujemo u poruci: „Ukupan broj blokova dodatih u blockchain“,
                                                                        //a taj broj je, naravno, unapred definisan — ukupno 3 bloka.
    let bekcoin_per_block: usize = 137; //Zatim postavljam cenu Bitcoina po bloku.

    let bekcoin_traded: usize = total_blocks * bekcoin_per_block;   //i to množimo sa ukupnim brojem blokovakako bismo dobili ukupnu količinu Bitcoina kojom se trgovalo.

    println!("Total bekcoin traded: {} Bekcoin", bekcoin_traded);   //Zatim to ispisujemo.

    let end_timestamp: u64 = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs();  //Nakon toga uzimamo trenutnu vremensku oznaku —

    let end_datetime: Option<NaiveDateTime> = chrono::NaiveDateTime::from_timestamp_opt(end_timestamp as i64, 0); //Zatim konvertujemo timestamp u datum i vreme (datetime) i

    println!("Simulation ended at: {:?}", end_datetime);  //ispisujemo taj datum i vreme.

    println!("Congrats! Mining operation completed successfully"); //Na kraju ispisujemo poruku čestitke.
}