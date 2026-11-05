//! The request builder and pagination.

use std::future::{Future, IntoFuture};
use std::pin::Pin;

use futures_util::stream::{self, Stream, TryStreamExt};
use serde_json::Value;

use crate::client::Client;
use crate::config::Validation;
use crate::error::Result;
use crate::params::{ParamValue, Params};
use crate::response::Response;

/// Default page size for [`Request::all`]; matches the server's default `default.page.size`.
pub const DEFAULT_PAGE_SIZE: u32 = 500;

/// A pending API call. Await it directly, or call [`Request::send`].
///
/// ```no_run
/// # async fn f(client: cloudstack_rs::Client) -> cloudstack_rs::Result<()> {
/// let vms = client.request("listVirtualMachines").param("state", "Running").await?;
/// # Ok(()) }
/// ```
#[derive(Clone, Debug)]
#[must_use = "a request does nothing until it is awaited"]
pub struct Request {
    pub(crate) client: Client,
    pub(crate) command: String,
    pub(crate) params: Params,
    pub(crate) wait: bool,
    pub(crate) validation: Option<Validation>,
}

impl Request {
    pub(crate) fn new(client: Client, command: String) -> Self {
        Self {
            client,
            command,
            params: Params::new(),
            wait: true,
            validation: None,
        }
    }

    /// Sets a parameter. Names are matched case-insensitively against the API's declaration.
    pub fn param(mut self, name: impl Into<String>, value: impl Into<ParamValue>) -> Self {
        self.params.set(name, value);
        self
    }

    /// Sets a parameter when `value` is `Some`.
    pub fn param_opt(self, name: impl Into<String>, value: Option<impl Into<ParamValue>>) -> Self {
        match value {
            Some(v) => self.param(name, v),
            None => self,
        }
    }

    /// Adds several parameters.
    pub fn params<K: Into<String>, V: Into<ParamValue>>(mut self, params: impl IntoIterator<Item = (K, V)>) -> Self {
        self.params.extend(params);
        self
    }

    /// For async APIs: return as soon as the job is started instead of waiting for it.
    /// The response then holds `{jobid, id}` and [`Response::is_pending`] is true;
    /// use [`Client::wait_for_job`] or [`Client::query_job`] later.
    pub fn no_wait(mut self) -> Self {
        self.wait = false;
        self
    }

    /// Overrides the client's validation mode for this call.
    pub fn validation(mut self, validation: Validation) -> Self {
        self.validation = Some(validation);
        self
    }

    pub fn command(&self) -> &str {
        &self.command
    }

    pub fn get_params(&self) -> &Params {
        &self.params
    }

    /// Sends the request.
    pub async fn send(self) -> Result<Response> {
        let client = self.client.clone();
        client.execute_request(self).await
    }

    /// Pages through a list API, yielding one page of items at a time.
    pub fn pages(self, page_size: u32) -> impl Stream<Item = Result<Vec<Value>>> + Send + 'static {
        let page_size = page_size.max(1);
        stream::try_unfold((self, 1u32, 0u64, false), move |(req, page, seen, done)| async move {
            if done {
                return Ok(None);
            }
            let resp = req
                .clone()
                .param("page", page)
                .param("pagesize", page_size)
                .send()
                .await?;
            let total = resp.count();
            let items = resp.into_items();
            let seen = seen + items.len() as u64;
            let done = items.len() < page_size as usize || total.is_some_and(|t| seen >= t);
            if items.is_empty() {
                return Ok(None);
            }
            Ok(Some((items, (req, page + 1, seen, done))))
        })
    }

    /// Pages through a list API, yielding items one by one.
    pub fn items(self, page_size: u32) -> impl Stream<Item = Result<Value>> + Send + 'static {
        self.pages(page_size)
            .map_ok(|page| stream::iter(page.into_iter().map(Ok)))
            .try_flatten()
    }

    /// Fetches every item of a list API, [`DEFAULT_PAGE_SIZE`] at a time.
    pub async fn all(self) -> Result<Vec<Value>> {
        let pages: Vec<Vec<Value>> = self.pages(DEFAULT_PAGE_SIZE).try_collect().await?;
        Ok(pages.into_iter().flatten().collect())
    }
}

impl IntoFuture for Request {
    type Output = Result<Response>;
    type IntoFuture = Pin<Box<dyn Future<Output = Result<Response>> + Send + 'static>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.send())
    }
}
