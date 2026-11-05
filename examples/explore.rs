//! Browse the API catalog.
//!
//! Online (uses CLOUDSTACK_API_URL and credentials from the environment):
//!     cargo run --example explore -- [search-term | ApiName]
//! Offline, from a saved `listApis` response or CloudMonkey's `apis.json`:
//!     CLOUDSTACK_CATALOG=apis.json cargo run --example explore -- deployVirtualMachine

use cloudstack_rs::{ApiCatalog, Client};

#[tokio::main]
async fn main() -> cloudstack_rs::Result<()> {
    let catalog = match std::env::var("CLOUDSTACK_CATALOG") {
        Ok(path) => ApiCatalog::from_list_apis_json(&std::fs::read_to_string(path)?)?,
        Err(_) => Client::from_env()?.catalog().await?.as_ref().clone(),
    };
    let arg = std::env::args().nth(1);

    match arg.as_deref().map(|a| catalog.resolve(a)) {
        Some(Ok(api)) => {
            println!(
                "{} ({}){}",
                api.name,
                if api.is_async { "async" } else { "sync" },
                api.since.as_deref().map(|s| format!(", since {s}")).unwrap_or_default()
            );
            println!("  {}\n", api.description);
            let mut params: Vec<_> = api.params.iter().collect();
            params.sort_by_key(|p| (!p.required, p.name.clone()));
            for p in params {
                println!(
                    "  {}{:<28} {:<8} {}",
                    if p.required { "*" } else { " " },
                    p.name,
                    p.kind,
                    p.description
                );
            }
            if !api.related.is_empty() {
                println!("\n  related: {}", api.related.join(", "));
            }
        }
        Some(Err(_)) => {
            for api in catalog.search(arg.as_deref().unwrap_or_default()) {
                println!("{:<45} {}", api.name, api.description);
            }
        }
        None => {
            println!(
                "{} APIs, server version {}",
                catalog.len(),
                catalog.server_version().unwrap_or("unknown")
            );
            for verb in catalog.verbs() {
                println!("  {verb:<16} {}", catalog.with_verb(verb).count());
            }
        }
    }
    Ok(())
}
