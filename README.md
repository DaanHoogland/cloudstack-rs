# cloudstack-rs

An async Rust client for the [Apache CloudStack](https://cloudstack.apache.org) API that
discovers the available APIs at runtime.

The client has no generated bindings for one CloudStack release. It asks the management server
what it offers (`listApis`) and uses that catalog to:

- resolve API names, including CloudMonkey's `verb noun` form (`"list virtualmachines"`),
- know which APIs are asynchronous, and poll their jobs to completion,
- validate parameters before sending them: required, unknown (with "did you mean"), type, and
  maximum length,
- expose the API metadata for introspection (descriptions, parameters, related APIs, response
  fields).

A new server version's APIs work immediately, and only what the account's role permits is
offered.

## Using it

The package is `cloudstack-rs`; in code it is `cloudstack_rs`. Until it is published, depend
on it by path (or by git URL once it has a repository):

```toml
[dependencies]
cloudstack-rs = { path = "../cloudstack-rs" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust
use cloudstack_rs::{Client, ParamValue};

#[tokio::main]
async fn main() -> cloudstack_rs::Result<()> {
    let client = Client::builder("https://cloud.example.com/client/api")
        .api_key("API_KEY", "SECRET_KEY")
        .build()?;

    // A request is a future: build it, then await it.
    let zones = client.request("listZones").param("available", true).await?;
    for zone in zones.items() {
        println!("{} {}", zone["id"], zone["name"]);
    }

    // Follow pages automatically (or stream them with `.items(page_size)` / `.pages(...)`).
    let running = client.request("list virtualmachines").param("state", "Running").all().await?;

    // Async APIs are waited for; the response is the job result.
    let vm = client
        .request("deployVirtualMachine")
        .param("zoneid", "...")
        .param("serviceofferingid", "...")
        .param("templateid", "...")
        .param("details", ParamValue::map([("cpuNumber", "2"), ("memory", "2048")]))
        .param("tags", ParamValue::key_values([("env", "prod")]))  // only on APIs with a `tags` map
        .await?;
    println!("{}", vm.entity().unwrap()["id"]);

    // Or start the job and check on it later.
    let started = client.request("stopVirtualMachine").param("id", "...").no_wait().await?;
    let job_id = &started.job().unwrap().job_id;
    let done = client.wait_for_job(job_id).await?;
    Ok(())
}
```

Typed access is available on any response via serde: `resp.deserialize_items::<MyVm>()`,
`resp.deserialize_entity::<MyVm>()`.

## Configuration

| Builder method | Default | Notes |
|---|---|---|
| `api_key(key, secret)` / `password(user, pass, domain)` | — | `Client::from_env()` reads `CLOUDSTACK_API_URL`, `CLOUDSTACK_API_KEY`, `CLOUDSTACK_SECRET_KEY` (or `CLOUDSTACK_USERNAME`, `CLOUDSTACK_PASSWORD`, `CLOUDSTACK_DOMAIN`), the same variables as the Terraform provider |
| `signature_algorithm` | `HmacSha1` | `HmacSha512`, or `Auto` (try SHA512, fall back to SHA1, remember the result) |
| `signature_validity` | 10 min | `signatureversion=3` + `expires`; `None` for version 1 signatures |
| `http_method` | `Post` | `Get`, or `Auto` (GET unless secrets or a long query) |
| `discovery` | `Lazy` | `Disabled` sends commands blind; `.catalog(c)` supplies a catalog yourself |
| `discovery_cache` | off | `DiscoveryCache::default_location()` persists catalogs, 24h TTL |
| `validation` | `Strict` | `Warn`, `Off`; can be overridden per request |
| `poll_config` / `async_timeout` | 0.5s → 10s backoff, 1h | |
| `two_factor_provider` | none | async callback supplying a 2FA code at password login |
| `timeout`, `connect_timeout`, `accept_invalid_certs`, `http_client` | 120s, 15s, false | |

## Differences from cloudstack-go and CloudMonkey

Both were the starting point. These are the deliberate changes:

- **Signing matches the server.** The server rebuilds the string to sign with Java's
  `URLEncoder`. Both Go clients use `url.QueryEscape`, which leaves `~` unescaped where Java
  escapes it, so values containing `~` produce signatures the server rejects. This crate encodes
  exactly as `URLEncoder` does. Tests check it against reference signatures computed separately
  in Python, and against a mock server that verifies signatures the way the real one does.
- **Works with `enforce.post.requests.and.timestamps`.** Requests are POSTed by default and expire
  after 10 minutes. The server rejects anything more than 15 minutes ahead; the Go clients send
  exactly 15, which leaves no room for clock skew. POST also keeps passwords and userdata out of
  URLs and access logs.
- **Discovery is per identity.** `listApis` depends on the caller's role, so the optional disk
  cache is keyed by a hash of endpoint plus identity. A root admin's catalog is never reused for
  a user, and no credentials are stored. The cache also records the server version.
- **Validation before sending.** Missing or unknown parameters (with suggestions), malformed
  booleans and numbers, maps passed as scalars and over-long strings are reported together,
  without a round trip. Parameter-name case is normalised (`zoneId` → `zoneid`).
- **Structured errors.** `errorcode`, `cserrorcode`, `errortext` and the HTTP status are typed
  fields. Failed jobs carry their error and raw result, and timeouts are a separate variant.
- **Pagination as a stream.** `pages()`, `items()` and `all()` stop on `count` or a short
  page.
- **Library-first async.** The client is `Clone + Send + Sync` and shares its connection pool,
  session and catalog. Requests are `IntoFuture`. Session logins happen lazily, and the client
  logs in again on 401. Async-job polling backs off exponentially and has a deadline.
- **No hidden state.** Nothing touches disk unless a cache is configured, and secrets are
  redacted from `Debug` output and logs.

## Examples

```sh
export CLOUDSTACK_API_URL=http://localhost:8080/client/api
export CLOUDSTACK_API_KEY=... CLOUDSTACK_SECRET_KEY=...
cargo run --example call -- list zones available=true
cargo run --example explore -- deployVirtualMachine     # describe an API
cargo run --example explore -- kubernetes               # search the catalog
CLOUDSTACK_CATALOG=apis.json cargo run --example explore # offline, e.g. CloudMonkey's apis.json
```

## Status / next steps

API layer only. Not done yet:

- Integration tests against a live management server or simulator. Everything so far is unit
  tests plus a mock server.
- Optional typed wrappers generated from a catalog, behind a feature flag, for compile-time
  checked calls.
- File uploads (`getUploadParamsFor*` + POST), as CloudMonkey does.
- Reading CloudMonkey's `~/.cmk/config` profiles.

## License

Apache-2.0
