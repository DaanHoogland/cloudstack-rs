//! The client: transport, authentication, discovery and async jobs.

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Instant;

use chrono::{SecondsFormat, Utc};
use serde_json::Value;
use tokio::sync::{Mutex, RwLock};
use url::Url;

use crate::cache::DiscoveryCache;
use crate::config::{
    ClientBuilder, Credentials, Discovery, HttpMethod, PollConfig, TwoFactorProvider, Validation, normalize_endpoint,
};
use crate::discovery::{ApiCatalog, ApiInfo};
use crate::error::{Error, Result};
use crate::params::{Params, base_name};
use crate::request::Request;
use crate::response::{JobInfo, JobState, JobStatus, Response, parse_body};
use crate::signing::{self, Digest, SignatureAlgorithm};
use crate::util::{lenient_bool, lenient_string};

/// Parameters the client sets itself; user-supplied values for these are dropped.
const RESERVED: &[&str] = &[
    "command",
    "response",
    "apikey",
    "signature",
    "signatureversion",
    "expires",
    "sessionkey",
];

/// Parameter names whose values should never end up in a URL.
const SENSITIVE: &[&str] = &["password", "userdata", "secret", "privatekey", "certificate"];

/// An async CloudStack API client. Cheap to clone; clones share connections, session and catalog.
#[derive(Clone)]
pub struct Client {
    inner: Arc<Inner>,
}

struct Inner {
    http: reqwest::Client,
    endpoint: Url,
    auth: Auth,
    signature_validity: Option<std::time::Duration>,
    http_method: HttpMethod,
    post_threshold: usize,
    poll: PollConfig,
    discovery: Discovery,
    validation: Validation,
    cache: Option<DiscoveryCache>,
    catalog: RwLock<Option<Arc<ApiCatalog>>>,
    catalog_load: Mutex<()>,
}

enum Auth {
    Keys {
        api_key: String,
        secret_key: String,
        algorithm: SignatureAlgorithm,
        /// For `Auto`: 0 = not yet known, 1 = SHA1, 2 = SHA512.
        detected: AtomicU8,
    },
    Session {
        username: String,
        password: String,
        domain: Option<String>,
        session_key: Mutex<Option<String>>,
        two_factor: Option<TwoFactorProvider>,
    },
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("endpoint", &self.inner.endpoint.as_str())
            .finish_non_exhaustive()
    }
}

impl Client {
    /// Starts configuring a client for `endpoint`.
    pub fn builder(endpoint: impl Into<String>) -> ClientBuilder {
        ClientBuilder::new(endpoint)
    }

    /// A client configured from environment variables (see [`ClientBuilder::from_env`]).
    pub fn from_env() -> Result<Self> {
        ClientBuilder::from_env()?.build()
    }

    pub(crate) fn from_builder(b: ClientBuilder) -> Result<Self> {
        let endpoint = normalize_endpoint(&b.endpoint)?;
        let credentials = b
            .credentials
            .ok_or_else(|| Error::Config("no credentials configured".into()))?;
        if b.poll.multiplier < 1.0 || b.poll.initial_interval.is_zero() {
            return Err(Error::Config(
                "poll interval must be positive and must not shrink".into(),
            ));
        }
        let http = match b.http_client {
            Some(c) => c,
            None => reqwest::Client::builder()
                .cookie_store(true)
                .timeout(b.timeout)
                .connect_timeout(b.connect_timeout)
                .danger_accept_invalid_certs(b.accept_invalid_certs)
                .user_agent(b.user_agent)
                .build()?,
        };
        let auth = match credentials {
            Credentials::ApiKey { api_key, secret_key } => Auth::Keys {
                api_key,
                secret_key,
                algorithm: b.signature_algorithm,
                detected: AtomicU8::new(0),
            },
            Credentials::Password {
                username,
                password,
                domain,
            } => Auth::Session {
                username,
                password,
                domain,
                session_key: Mutex::new(None),
                two_factor: b.two_factor,
            },
        };
        Ok(Client {
            inner: Arc::new(Inner {
                http,
                endpoint,
                auth,
                signature_validity: b.signature_validity,
                http_method: b.http_method,
                post_threshold: b.post_threshold,
                poll: b.poll,
                discovery: b.discovery,
                validation: b.validation,
                cache: b.cache,
                catalog: RwLock::new(b.catalog.map(Arc::new)),
                catalog_load: Mutex::new(()),
            }),
        })
    }

    /// The API endpoint URL.
    pub fn endpoint(&self) -> &Url {
        &self.inner.endpoint
    }

    /// Starts a call to `command`: an API name (`listVirtualMachines`, any case) or
    /// CloudMonkey-style `verb noun` (`"list virtualmachines"`).
    pub fn request(&self, command: impl Into<String>) -> Request {
        Request::new(self.clone(), command.into())
    }

    /// Calls `command` with `params`; same as `self.request(command).params(params).send()`.
    pub async fn execute(&self, command: &str, params: Params) -> Result<Response> {
        self.request(command).params(params).send().await
    }

    // ---- discovery ------------------------------------------------------------------------

    /// The API catalog, discovering it (or loading it from the disk cache) on first use.
    pub async fn catalog(&self) -> Result<Arc<ApiCatalog>> {
        if let Some(c) = self.inner.catalog.read().await.clone() {
            return Ok(c);
        }
        let _loading = self.inner.catalog_load.lock().await;
        if let Some(c) = self.inner.catalog.read().await.clone() {
            return Ok(c);
        }
        if let Some(cache) = &self.inner.cache {
            if let Some(catalog) = cache.load(self.inner.endpoint.as_str(), &self.identity()) {
                tracing::debug!(apis = catalog.len(), "loaded API catalog from disk cache");
                let catalog = Arc::new(catalog);
                *self.inner.catalog.write().await = Some(catalog.clone());
                return Ok(catalog);
            }
        }
        self.refresh_catalog().await
    }

    /// The catalog if it is already loaded; never touches the network.
    pub async fn cached_catalog(&self) -> Option<Arc<ApiCatalog>> {
        self.inner.catalog.read().await.clone()
    }

    /// Fetches a fresh catalog with `listApis` (e.g. after an upgrade or a role change).
    pub async fn refresh_catalog(&self) -> Result<Arc<ApiCatalog>> {
        let body = self.send_command("listApis", Params::new()).await?;
        let mut catalog = ApiCatalog::from_list_apis(&body)?;
        match self.send_command("listCapabilities", Params::new()).await {
            Ok(caps) => {
                catalog.set_server_version(caps.pointer("/capability/cloudstackversion").and_then(lenient_string))
            }
            Err(e) => tracing::debug!(error = %e, "listCapabilities failed; server version unknown"),
        }
        tracing::debug!(apis = catalog.len(), version = ?catalog.server_version(), "discovered API catalog");
        if let Some(cache) = &self.inner.cache {
            if let Err(e) = cache.store(self.inner.endpoint.as_str(), &self.identity(), &catalog) {
                tracing::warn!(error = %e, dir = %cache.dir().display(), "could not write API cache");
            }
        }
        let catalog = Arc::new(catalog);
        *self.inner.catalog.write().await = Some(catalog.clone());
        Ok(catalog)
    }

    /// Metadata of one API.
    pub async fn api(&self, name: &str) -> Result<ApiInfo> {
        Ok(self.catalog().await?.resolve(name)?.clone())
    }

    fn identity(&self) -> String {
        match &self.inner.auth {
            Auth::Keys { api_key, .. } => format!("key:{api_key}"),
            Auth::Session { username, domain, .. } => format!("user:{username}@{}", domain.as_deref().unwrap_or("/")),
        }
    }

    // ---- high-level execution ----------------------------------------------------------------

    pub(crate) async fn execute_request(&self, req: Request) -> Result<Response> {
        let Request {
            command,
            mut params,
            wait,
            validation,
            ..
        } = req;
        let api = match (self.inner.discovery, self.cached_catalog().await) {
            (_, Some(c)) => Some(c.resolve(&command)?.clone()),
            (Discovery::Lazy, None) => Some(self.catalog().await?.resolve(&command)?.clone()),
            (Discovery::Disabled, None) => None,
        };
        let command = api.as_ref().map_or(command, |a| a.name.clone());

        if let Some(api) = &api {
            api.canonicalize(&mut params);
            match validation.unwrap_or(self.inner.validation) {
                Validation::Off => {}
                mode => {
                    let problems = api.validate(&params);
                    if !problems.is_empty() {
                        if mode == Validation::Strict {
                            return Err(Error::InvalidParams { api: command, problems });
                        }
                        for p in &problems {
                            tracing::warn!(api = %command, "{p}");
                        }
                    }
                }
            }
        }

        let body = self.send_command(&command, params).await?;

        let job_id = body.get("jobid").and_then(lenient_string);
        let is_async = match &api {
            Some(api) => api.is_async,
            // Without metadata: async responses are just `{jobid[, id]}`.
            None => job_id.is_some() && body.as_object().is_some_and(|o| o.len() <= 2),
        };
        match job_id {
            Some(job_id) if is_async && wait => self.await_job(command, &job_id).await,
            Some(job_id) if is_async => {
                let instance_id = body.get("id").and_then(lenient_string);
                Ok(Response::new(
                    command,
                    body,
                    Some(JobInfo::pending(job_id, instance_id)),
                ))
            }
            _ => Ok(Response::new(command, body, None)),
        }
    }

    // ---- async jobs ----------------------------------------------------------------------------

    /// One `queryAsyncJobResult` call.
    pub async fn query_job(&self, job_id: &str) -> Result<JobState> {
        let body = self
            .send_command("queryAsyncJobResult", Params::new().with("jobid", job_id))
            .await?;
        Ok(JobState::from_query(job_id, body))
    }

    /// Polls a job until it finishes; the response holds its `jobresult`.
    pub async fn wait_for_job(&self, job_id: &str) -> Result<Response> {
        self.await_job("queryAsyncJobResult".to_owned(), job_id).await
    }

    async fn await_job(&self, command: String, job_id: &str) -> Result<Response> {
        let poll = &self.inner.poll;
        let start = Instant::now();
        let mut interval = poll.initial_interval;
        loop {
            let remaining = poll.timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                return Err(Error::JobTimeout {
                    job_id: job_id.to_owned(),
                    timeout: poll.timeout,
                });
            }
            tokio::time::sleep(interval.min(remaining)).await;
            interval = interval.mul_f64(poll.multiplier).min(poll.max_interval);

            let state = self.query_job(job_id).await?;
            match state.info.status {
                JobStatus::Succeeded => return Ok(Response::new(command, state.result, Some(state.info))),
                JobStatus::Failed => {
                    return Err(Error::JobFailed {
                        job_id: job_id.to_owned(),
                        error: state.error(),
                        result: state.result,
                    });
                }
                JobStatus::Pending => tracing::trace!(job_id, "job still running"),
                JobStatus::Unknown(s) => tracing::debug!(job_id, status = s, "unexpected job status"),
            }
        }
    }

    // ---- sessions ------------------------------------------------------------------------------

    /// Logs in now instead of on the first call (password credentials only; a no-op otherwise).
    pub async fn login(&self) -> Result<()> {
        if let Auth::Session { .. } = &self.inner.auth {
            self.session_key(true).await?;
        }
        Ok(())
    }

    /// Ends the session (password credentials only; a no-op otherwise).
    pub async fn logout(&self) -> Result<()> {
        if let Auth::Session { session_key, .. } = &self.inner.auth {
            let key = session_key.lock().await.take();
            if let Some(key) = key {
                let pairs = vec![
                    ("command".to_owned(), "logout".to_owned()),
                    ("response".to_owned(), "json".to_owned()),
                    ("sessionkey".to_owned(), key),
                ];
                self.transmit(pairs, true).await?;
            }
        }
        Ok(())
    }

    async fn session_key(&self, force_login: bool) -> Result<String> {
        let Auth::Session { session_key, .. } = &self.inner.auth else {
            unreachable!("session_key is only used with password credentials");
        };
        let mut guard = session_key.lock().await;
        if !force_login {
            if let Some(key) = guard.as_ref() {
                return Ok(key.clone());
            }
        }
        let key = self.do_login().await?;
        *guard = Some(key.clone());
        Ok(key)
    }

    async fn do_login(&self) -> Result<String> {
        let Auth::Session {
            username,
            password,
            domain,
            two_factor,
            ..
        } = &self.inner.auth
        else {
            unreachable!("login is only used with password credentials");
        };
        let mut form = vec![
            ("command", "login".to_owned()),
            ("response", "json".to_owned()),
            ("username", username.clone()),
            ("password", password.clone()),
        ];
        if let Some(domain) = domain {
            form.push(("domain", domain.clone()));
        }
        tracing::debug!(username, "logging in");
        let resp = self
            .inner
            .http
            .post(self.inner.endpoint.clone())
            .form(&form)
            .send()
            .await?;
        let cookie_key = resp
            .cookies()
            .find(|c| c.name() == "sessionkey")
            .map(|c| c.value().to_owned());
        let status = resp.status().as_u16();
        let body = parse_body(status, &resp.bytes().await?)?;

        let key = body
            .get("sessionkey")
            .and_then(lenient_string)
            .or(cookie_key)
            .ok_or_else(|| Error::UnexpectedResponse {
                status,
                message: "login response carries no session key".into(),
            })?;

        let flag = |k: &str| body.get(k).and_then(lenient_bool).unwrap_or(false);
        if flag("is2faenabled") && !flag("is2faverified") {
            let provider = two_factor.as_ref().ok_or(Error::TwoFactorRequired)?;
            let code = provider().await?;
            let form = [
                ("command", "validateUserTwoFactorAuthenticationCode".to_owned()),
                ("response", "json".to_owned()),
                ("codefor2fa", code),
                ("sessionkey", key.clone()),
            ];
            let resp = self
                .inner
                .http
                .post(self.inner.endpoint.clone())
                .form(&form)
                .send()
                .await?;
            let status = resp.status().as_u16();
            parse_body(status, &resp.bytes().await?)?;
        }
        Ok(key)
    }

    // ---- transport -----------------------------------------------------------------------------

    /// Sends one command, authenticated, and returns the unwrapped body. No catalog involved.
    pub(crate) async fn send_command(&self, command: &str, mut params: Params) -> Result<Value> {
        params.retain(|k| {
            let reserved = RESERVED.iter().any(|r| k.eq_ignore_ascii_case(r));
            if reserved {
                tracing::warn!(param = k, "ignoring parameter that the client sets itself");
            }
            !reserved
        });
        let mut pairs = params.flatten();
        pairs.push(("command".to_owned(), command.to_owned()));
        pairs.push(("response".to_owned(), "json".to_owned()));
        tracing::debug!(command, "calling CloudStack API");

        match &self.inner.auth {
            Auth::Keys {
                algorithm, detected, ..
            } => {
                let candidates: &[Digest] = match (algorithm, detected.load(Ordering::Relaxed)) {
                    (SignatureAlgorithm::HmacSha1, _) | (SignatureAlgorithm::Auto, 1) => &[Digest::Sha1],
                    (SignatureAlgorithm::HmacSha512, _) | (SignatureAlgorithm::Auto, 2) => &[Digest::Sha512],
                    (SignatureAlgorithm::Auto, _) => &[Digest::Sha512, Digest::Sha1],
                };
                let mut result = Err(Error::Config("no signature algorithm".into()));
                for (i, digest) in candidates.iter().enumerate() {
                    result = self.send_signed(pairs.clone(), *digest).await;
                    match &result {
                        Err(e) if e.is_auth_failure() && i + 1 < candidates.len() => {
                            tracing::debug!(?digest, "signature rejected, trying next algorithm");
                        }
                        Ok(_) if *algorithm == SignatureAlgorithm::Auto => {
                            detected.store(if *digest == Digest::Sha1 { 1 } else { 2 }, Ordering::Relaxed);
                            break;
                        }
                        _ => break,
                    }
                }
                result
            }
            Auth::Session { .. } => {
                for attempt in 0..2 {
                    let key = self.session_key(attempt > 0).await?;
                    let mut p = pairs.clone();
                    p.push(("sessionkey".to_owned(), key));
                    match self.transmit(p, false).await {
                        Err(e) if e.is_auth_failure() && attempt == 0 => {
                            tracing::debug!("session rejected, logging in again");
                        }
                        other => return other,
                    }
                }
                unreachable!("the second attempt always returns")
            }
        }
    }

    async fn send_signed(&self, mut pairs: Vec<(String, String)>, digest: Digest) -> Result<Value> {
        let Auth::Keys {
            api_key, secret_key, ..
        } = &self.inner.auth
        else {
            unreachable!("signing is only used with API keys");
        };
        pairs.push(("apiKey".to_owned(), api_key.clone()));
        if let Some(validity) = self.inner.signature_validity {
            let expires = Utc::now() + validity;
            pairs.push(("signatureversion".to_owned(), "3".to_owned()));
            pairs.push(("expires".to_owned(), expires.to_rfc3339_opts(SecondsFormat::Secs, true)));
        }
        signing::sort_params(&mut pairs);
        let signature = signing::sign(&signing::string_to_sign(&pairs), secret_key, digest);
        pairs.push(("signature".to_owned(), signature));
        self.transmit(pairs, false).await
    }

    async fn transmit(&self, pairs: Vec<(String, String)>, force_post: bool) -> Result<Value> {
        let query = signing::query_string(&pairs);
        let post = force_post
            || match self.inner.http_method {
                HttpMethod::Post => true,
                HttpMethod::Get => false,
                HttpMethod::Auto => {
                    query.len() > self.inner.post_threshold
                        || pairs.iter().any(|(k, _)| {
                            let k = base_name(k).to_ascii_lowercase();
                            SENSITIVE.iter().any(|s| k.contains(s))
                        })
                }
            };
        let request = if post {
            self.inner.http.post(self.inner.endpoint.clone()).form(&pairs)
        } else {
            let mut url = self.inner.endpoint.clone();
            url.set_query(Some(&query));
            self.inner.http.get(url)
        };
        let resp = request.send().await?;
        let status = resp.status().as_u16();
        let bytes = resp.bytes().await?;
        // Bodies are not logged: some (getUserKeys, registerUserKeys) contain secrets.
        tracing::trace!(status, bytes = bytes.len(), "CloudStack response");
        parse_body(status, &bytes)
    }
}
