//! Client configuration.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use url::Url;

use crate::cache::DiscoveryCache;
use crate::client::Client;
use crate::discovery::ApiCatalog;
use crate::error::{Error, Result};
use crate::signing::SignatureAlgorithm;

/// How to authenticate.
#[derive(Clone)]
pub enum Credentials {
    /// Signed requests with an API key pair (recommended for automation).
    ApiKey { api_key: String, secret_key: String },
    /// Session login with username and password. `domain` is the domain path (`/` = ROOT).
    Password {
        username: String,
        password: String,
        domain: Option<String>,
    },
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Credentials::ApiKey { api_key, .. } => f
                .debug_struct("ApiKey")
                .field("api_key", api_key)
                .field("secret_key", &"<redacted>")
                .finish(),
            Credentials::Password { username, domain, .. } => f
                .debug_struct("Password")
                .field("username", username)
                .field("password", &"<redacted>")
                .field("domain", domain)
                .finish(),
        }
    }
}

/// Which HTTP method carries API calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpMethod {
    /// Always POST (form body). Works on every server, including ones with
    /// `enforce.post.requests.and.timestamps` enabled, and keeps parameters out of access logs.
    #[default]
    Post,
    /// Always GET (query string).
    Get,
    /// GET, unless the request carries secrets (passwords, keys, userdata) or its query string
    /// exceeds the POST threshold.
    Auto,
}

/// Whether the client discovers APIs with `listApis`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Discovery {
    /// Fetch the catalog on first use (or load it from the disk cache).
    #[default]
    Lazy,
    /// Never call `listApis`. Commands are sent as given, without validation, and async jobs
    /// are recognised by the `jobid` in the response. A catalog given to
    /// [`ClientBuilder::catalog`] is still used.
    Disabled,
}

/// What to do when parameters do not match the discovered API metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Validation {
    /// Refuse to send the request ([`Error::InvalidParams`]).
    #[default]
    Strict,
    /// Log a warning and send it anyway.
    Warn,
    /// Do not check.
    Off,
}

/// How async jobs are polled.
#[derive(Debug, Clone)]
pub struct PollConfig {
    /// Delay before the first `queryAsyncJobResult`.
    pub initial_interval: Duration,
    /// Upper bound for the delay between polls.
    pub max_interval: Duration,
    /// Factor the delay grows by after each poll.
    pub multiplier: f64,
    /// Give up after this long ([`Error::JobTimeout`]). The job keeps running on the server.
    pub timeout: Duration,
}

impl Default for PollConfig {
    fn default() -> Self {
        Self {
            initial_interval: Duration::from_millis(500),
            max_interval: Duration::from_secs(10),
            multiplier: 1.5,
            timeout: Duration::from_secs(3600),
        }
    }
}

/// Future returned by a two-factor code provider.
pub type TwoFactorFuture = Pin<Box<dyn Future<Output = Result<String>> + Send>>;
pub(crate) type TwoFactorProvider = Arc<dyn Fn() -> TwoFactorFuture + Send + Sync>;

/// Builds a [`Client`].
pub struct ClientBuilder {
    pub(crate) endpoint: String,
    pub(crate) credentials: Option<Credentials>,
    pub(crate) signature_algorithm: SignatureAlgorithm,
    pub(crate) signature_validity: Option<Duration>,
    pub(crate) timeout: Duration,
    pub(crate) connect_timeout: Duration,
    pub(crate) accept_invalid_certs: bool,
    pub(crate) user_agent: String,
    pub(crate) http_client: Option<reqwest::Client>,
    pub(crate) http_method: HttpMethod,
    pub(crate) post_threshold: usize,
    pub(crate) poll: PollConfig,
    pub(crate) discovery: Discovery,
    pub(crate) catalog: Option<ApiCatalog>,
    pub(crate) cache: Option<DiscoveryCache>,
    pub(crate) validation: Validation,
    pub(crate) two_factor: Option<TwoFactorProvider>,
}

impl ClientBuilder {
    /// `endpoint` is the API URL, e.g. `https://cloud.example.com/client/api`. When only a host
    /// is given (`https://cloud.example.com:8080`), `/client/api` is appended.
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            credentials: None,
            signature_algorithm: SignatureAlgorithm::default(),
            signature_validity: Some(Duration::from_secs(600)),
            timeout: Duration::from_secs(120),
            connect_timeout: Duration::from_secs(15),
            accept_invalid_certs: false,
            user_agent: concat!("cloudstack-rs/", env!("CARGO_PKG_VERSION")).to_owned(),
            http_client: None,
            http_method: HttpMethod::default(),
            post_threshold: 2048,
            poll: PollConfig::default(),
            discovery: Discovery::default(),
            catalog: None,
            cache: None,
            validation: Validation::default(),
            two_factor: None,
        }
    }

    /// Reads the same environment variables as the CloudStack Terraform provider:
    /// `CLOUDSTACK_API_URL` plus either `CLOUDSTACK_API_KEY` / `CLOUDSTACK_SECRET_KEY` or
    /// `CLOUDSTACK_USERNAME` / `CLOUDSTACK_PASSWORD` / `CLOUDSTACK_DOMAIN` (optional).
    pub fn from_env() -> Result<Self> {
        let var = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
        let endpoint =
            var("CLOUDSTACK_API_URL").ok_or_else(|| Error::Config("CLOUDSTACK_API_URL is not set".into()))?;
        let builder = Self::new(endpoint);
        if let (Some(key), Some(secret)) = (var("CLOUDSTACK_API_KEY"), var("CLOUDSTACK_SECRET_KEY")) {
            Ok(builder.api_key(key, secret))
        } else if let (Some(user), Some(pass)) = (var("CLOUDSTACK_USERNAME"), var("CLOUDSTACK_PASSWORD")) {
            Ok(builder.password(user, pass, var("CLOUDSTACK_DOMAIN")))
        } else {
            Err(Error::Config(
                "set CLOUDSTACK_API_KEY and CLOUDSTACK_SECRET_KEY, or CLOUDSTACK_USERNAME and CLOUDSTACK_PASSWORD"
                    .into(),
            ))
        }
    }

    /// Authenticate with an API key pair.
    pub fn api_key(mut self, api_key: impl Into<String>, secret_key: impl Into<String>) -> Self {
        self.credentials = Some(Credentials::ApiKey {
            api_key: api_key.into(),
            secret_key: secret_key.into(),
        });
        self
    }

    /// Authenticate with a session login.
    pub fn password(
        mut self,
        username: impl Into<String>,
        password: impl Into<String>,
        domain: Option<String>,
    ) -> Self {
        self.credentials = Some(Credentials::Password {
            username: username.into(),
            password: password.into(),
            domain,
        });
        self
    }

    pub fn credentials(mut self, credentials: Credentials) -> Self {
        self.credentials = Some(credentials);
        self
    }

    /// HMAC used for API key signatures. Default: [`SignatureAlgorithm::HmacSha1`].
    pub fn signature_algorithm(mut self, algorithm: SignatureAlgorithm) -> Self {
        self.signature_algorithm = algorithm;
        self
    }

    /// How long a signed request stays valid (`signatureversion=3` + `expires`). Default: 10
    /// minutes. Servers enforcing timestamps reject anything above 15 minutes. `None` sends
    /// unexpiring (version 1) signatures.
    pub fn signature_validity(mut self, validity: Option<Duration>) -> Self {
        self.signature_validity = validity;
        self
    }

    /// Timeout of a single HTTP request. Default: 120 seconds.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Skip TLS certificate verification. Only for test installations.
    pub fn accept_invalid_certs(mut self, accept: bool) -> Self {
        self.accept_invalid_certs = accept;
        self
    }

    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    /// Use your own `reqwest::Client` (proxies, custom roots, ...). Timeouts, TLS and user-agent
    /// settings of this builder are then ignored. Password login needs its cookie store enabled.
    pub fn http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = Some(client);
        self
    }

    pub fn http_method(mut self, method: HttpMethod) -> Self {
        self.http_method = method;
        self
    }

    /// Query string length above which [`HttpMethod::Auto`] switches to POST. Default: 2048.
    pub fn post_threshold(mut self, bytes: usize) -> Self {
        self.post_threshold = bytes;
        self
    }

    pub fn poll_config(mut self, poll: PollConfig) -> Self {
        self.poll = poll;
        self
    }

    /// Shorthand for setting [`PollConfig::timeout`].
    pub fn async_timeout(mut self, timeout: Duration) -> Self {
        self.poll.timeout = timeout;
        self
    }

    pub fn discovery(mut self, discovery: Discovery) -> Self {
        self.discovery = discovery;
        self
    }

    /// Use this catalog instead of discovering one (e.g. loaded from a file for offline use).
    /// [`Client::refresh_catalog`] still replaces it with a fresh one.
    pub fn catalog(mut self, catalog: ApiCatalog) -> Self {
        self.catalog = Some(catalog);
        self
    }

    /// Persist discovered catalogs on disk. Off by default.
    pub fn discovery_cache(mut self, cache: DiscoveryCache) -> Self {
        self.cache = Some(cache);
        self
    }

    pub fn validation(mut self, validation: Validation) -> Self {
        self.validation = validation;
        self
    }

    /// Supplies the code when a password login requires two-factor authentication.
    pub fn two_factor_provider<F, Fut>(mut self, provider: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<String>> + Send + 'static,
    {
        self.two_factor = Some(Arc::new(move || Box::pin(provider()) as TwoFactorFuture));
        self
    }

    pub fn build(self) -> Result<Client> {
        Client::from_builder(self)
    }
}

impl fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientBuilder")
            .field("endpoint", &self.endpoint)
            .field("credentials", &self.credentials)
            .field("signature_algorithm", &self.signature_algorithm)
            .field("http_method", &self.http_method)
            .field("discovery", &self.discovery)
            .field("validation", &self.validation)
            .finish_non_exhaustive()
    }
}

pub(crate) fn normalize_endpoint(endpoint: &str) -> Result<Url> {
    let mut url =
        Url::parse(endpoint.trim()).map_err(|e| Error::Config(format!("invalid endpoint `{endpoint}`: {e}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Error::Config(format!(
            "endpoint must be http(s), got `{}`",
            url.scheme()
        )));
    }
    if url.path().is_empty() || url.path() == "/" {
        url.set_path("/client/api");
    }
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints() {
        assert_eq!(
            normalize_endpoint("https://cs.example.com").unwrap().as_str(),
            "https://cs.example.com/client/api"
        );
        assert_eq!(
            normalize_endpoint("http://10.0.0.1:8080/client/api").unwrap().as_str(),
            "http://10.0.0.1:8080/client/api"
        );
        assert!(normalize_endpoint("ftp://x").is_err());
    }

    #[test]
    fn credentials_are_redacted() {
        let c = Credentials::ApiKey {
            api_key: "k".into(),
            secret_key: "s3cr3t".into(),
        };
        assert!(!format!("{c:?}").contains("s3cr3t"));
    }
}
