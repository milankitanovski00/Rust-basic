fn main() {
    let mut x = 5;
    println!("The value of x is: {x}");
    x = 6;
    println!("The value of x is: {x}");

    println!();

    //preklapanje promenljivih
    println!("Primer shadow - kada nova promenljiva zasenjuje staru");
    let a = 5;
    let a = a + 1;
    {
        let a = a *2;
        println!("The value of a in the inner scope is: {a}");
    }
    println!("The value of a is: {a}");

    println!();
    //funkcije sa povretnom vrednoscu
    let x = five();
    println!("The value of x is {x}");

    println!();
    let b = 5;
    let b = plus_one(b);
    print!("The value of b is {b}");


}

fn five() -> i32{
    5
}

fn plus_one(x:i32) -> i32 {
    x + 1
}