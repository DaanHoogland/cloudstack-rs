//! Call any API, CloudMonkey style:
//!
//!     export CLOUDSTACK_API_URL=http://localhost:8080/client/api
//!     export CLOUDSTACK_API_KEY=... CLOUDSTACK_SECRET_KEY=...
//!     cargo run --example call -- list virtualmachines state=Running
//!     cargo run --example call -- deployVirtualMachine zoneid=... templateid=... serviceofferingid=...
//!
//! `RUST_LOG=cloudstack_rs=debug` shows what is sent.

use cloudstack_rs::{Client, Params};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let (args, command): (Vec<String>, Vec<String>) = std::env::args().skip(1).partition(|a| a.contains('='));
    if command.is_empty() {
        eprintln!("usage: call <api | verb noun> [name=value ...]");
        std::process::exit(2);
    }
    let params: Params = args
        .iter()
        .filter_map(|a| a.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();

    let client = Client::from_env()?;
    match client.request(command.join(" ")).params(params).send().await {
        Ok(resp) => println!("{}", serde_json::to_string_pretty(resp.value())?),
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
    Ok(())
}
