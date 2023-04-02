mod buffer;

fn main() {
    println!("Hello, world!");
    let testing = String::from("Rbeard started");
    let mut buf = buffer::Buffer::new(testing.len() + 10);
    buf.putstring(testing.as_bytes(), testing.len());
    buf.setpos(0);
    let (string, retlen) = buf.getstring();
    println!("{} - {}", retlen, String::from_utf8(string).unwrap());

}
