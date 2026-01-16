fn main() {
    let width1 = 30;
    let height1 = 50;

     println!(
        "The area of the rectangle is {} square pixels.",
        area(width1, height1)
    );

    println!();
    println!("Racunanje povrsine sa koriscenjem torki");
    let rect1 = (30, 50);
    println!(
        "The area of the rectangle is {} square pixels.",
        area1(rect1)
    );

    println!();
    println!("Racunanje povrsine sa koriscenjem strukture");
    let rect2 = Rectangle {
        width: 30,
        height: 50,
    };
     println!(
        "The area of the rectangle is {} square pixels.",
        area2(&rect2)
    );

    println!();
    println!("Racunanje povrsine sa koriscenjem strukture i metode area");
    let rect3 = Rectangle1{
        width1: 30,
        height1: 50,
    };
    println!(
        "The area of the rectangle is {} square pixels.",
        rect3.area3()
    );

}

fn area(width: u32, height: u32) -> u32 {
    width * height
}

fn area1(dimensions: (u32, u32)) -> u32 {
    dimensions.0 * dimensions.1
}

struct Rectangle {
    width: u32,
    height: u32,
}

fn area2(rectangle: &Rectangle) -> u32{
    rectangle.height * rectangle.width
}

#[derive(Debug)]
struct Rectangle1 {
    width1: u32,
    height1: u32,
}

impl Rectangle1 {
    fn area3(&self) -> u32{
        self.height1 * self.width1
    }
}