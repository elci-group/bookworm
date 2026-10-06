mod auth;

fn main() {
    let token = auth::issue("user-1");
    println!("issued token: {token}");
}
