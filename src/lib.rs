//! An async client for the [Apache CloudStack](https://cloudstack.apache.org) API that learns
//! the available APIs at runtime.
//!
//! Instead of shipping generated bindings for one CloudStack release, the client asks the
//! server what it offers (`listApis`) and uses that catalog to resolve API names, recognise
//! async APIs, and validate parameters before a request is sent. New APIs and parameters work
//! as soon as the server has them, and only APIs the account's role allows are offered.
//!
//! ```no_run
//! use cloudstack_rs::{Client, ParamValue};
//!
//! # async fn run() -> cloudstack_rs::Result<()> {
//! let client = Client::builder("https://cloud.example.com/client/api")
//!     .api_key("API_KEY", "SECRET_KEY")
//!     .build()?;
//!
//! // A request is a future: build it, then await it.
//! let zones = client.request("listZones").param("available", true).await?;
//! for zone in zones.items() {
//!     println!("{} {}", zone["id"], zone["name"]);
//! }
//!
//! // CloudMonkey-style names work too; `all()` follows the pages.
//! let running = client.request("list virtualmachines").param("state", "Running").all().await?;
//!
//! // Async APIs are polled until the job is done; the response is the job result.
//! let vm = client
//!     .request("deployVirtualMachine")
//!     .param("zoneid", "...")
//!     .param("serviceofferingid", "...")
//!     .param("templateid", "...")
//!     .param("details", ParamValue::map([("cpuNumber", "2"), ("memory", "2048")]))
//!     .await?;
//! println!("deployed {}", vm.entity().unwrap()["id"]);
//! # Ok(()) }
//! ```
//!
//! Main types:
//!
//! * [`Client`] / [`ClientBuilder`]: connection, credentials, behaviour.
//! * [`Request`]: one call; await it, page through it, or start a job without waiting.
//! * [`Response`]: the unwrapped response with list, entity and deserialization helpers.
//! * [`ApiCatalog`] / [`ApiInfo`]: discovered API metadata, for validation and introspection.

mod cache;
mod client;
mod config;
mod discovery;
mod error;
mod params;
mod request;
mod response;
mod signing;
mod util;

pub use cache::DiscoveryCache;
pub use client::Client;
pub use config::{ClientBuilder, Credentials, Discovery, HttpMethod, PollConfig, TwoFactorFuture, Validation};
pub use discovery::{ApiCatalog, ApiInfo, ApiParam, ParamProblem, ParamType, ResponseField};
pub use error::{ApiError, Error, Result};
pub use params::{ParamValue, Params};
pub use request::{DEFAULT_PAGE_SIZE, Request};
pub use response::{JobInfo, JobState, JobStatus, Response};
pub use signing::SignatureAlgorithm;

/// Re-exported so callers can use the JSON values in responses without adding the dependency.
pub use serde_json;
