//! End-to-end tests against a mock management server.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use base64::Engine;
use cloudstack_rs::{
    Client, ClientBuilder, Discovery, DiscoveryCache, Error, HttpMethod, JobStatus, ParamProblem, ParamValue,
    PollConfig, SignatureAlgorithm, Validation,
};
use futures_util::TryStreamExt;
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use wiremock::matchers::method;
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

const KEY: &str = "test-api-key";
const SECRET: &str = "test-secret-key";

// ---- mock server helpers ------------------------------------------------------------------

/// All request parameters, from the query string or a form body.
fn params(req: &Request) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = req.url.query_pairs().into_owned().collect();
    if req.method.as_str() == "POST" {
        out.extend(url::form_urlencoded::parse(&req.body).into_owned());
    }
    out
}

fn param(req: &Request, name: &str) -> Option<String> {
    params(req).into_iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

struct Command(&'static str);
impl Match for Command {
    fn matches(&self, req: &Request) -> bool {
        param(req, "command").as_deref() == Some(self.0)
    }
}

struct HasParam(&'static str, &'static str);
impl Match for HasParam {
    fn matches(&self, req: &Request) -> bool {
        param(req, self.0).as_deref() == Some(self.1)
    }
}

/// Re-implements `ApiServer.verifyRequest` independently of the crate under test.
struct Signed {
    sha512: bool,
}
impl Match for Signed {
    fn matches(&self, req: &Request) -> bool {
        let mut pairs = params(req);
        let Some(pos) = pairs.iter().position(|(k, _)| k == "signature") else {
            return false;
        };
        let signature = pairs.remove(pos).1;
        pairs.sort();
        // application/x-www-form-urlencoded serialization has the same safe set as Java's URLEncoder
        let java = |v: &str| {
            url::form_urlencoded::byte_serialize(v.as_bytes())
                .collect::<String>()
                .replace('+', "%20")
        };
        let unsigned = pairs
            .iter()
            .map(|(k, v)| format!("{k}={}", java(v)))
            .collect::<Vec<_>>()
            .join("&")
            .to_lowercase();
        let digest = if self.sha512 {
            let mut m = Hmac::<sha2::Sha512>::new_from_slice(SECRET.as_bytes()).unwrap();
            m.update(unsigned.as_bytes());
            m.finalize().into_bytes().to_vec()
        } else {
            let mut m = Hmac::<sha1::Sha1>::new_from_slice(SECRET.as_bytes()).unwrap();
            m.update(unsigned.as_bytes());
            m.finalize().into_bytes().to_vec()
        };
        base64::engine::general_purpose::STANDARD.encode(digest) == signature
    }
}

fn ok(name: &str, body: Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({ format!("{}response", name.to_lowercase()): body }))
}

fn catalog_body() -> Value {
    json!({"count": 5, "api": [
        {"name": "listZones", "isasync": false, "description": "Lists zones",
         "params": [{"name": "available", "type": "boolean", "required": false},
                    {"name": "name", "type": "string", "required": false}]},
        {"name": "listVirtualMachines", "isasync": false, "description": "List the virtual machines",
         "params": [{"name": "page", "type": "integer"}, {"name": "pagesize", "type": "integer"},
                    {"name": "state", "type": "string"}]},
        {"name": "deployVirtualMachine", "isasync": true, "description": "Creates and starts a VM",
         "params": [{"name": "zoneid", "type": "uuid", "required": true},
                    {"name": "serviceofferingid", "type": "uuid", "required": true},
                    {"name": "templateid", "type": "uuid", "required": true},
                    {"name": "displayname", "type": "string"},
                    {"name": "userdata", "type": "string", "length": 1048576},
                    {"name": "details", "type": "map"}]},
        {"name": "queryAsyncJobResult", "isasync": false, "params": [{"name": "jobid", "type": "uuid", "required": true}]},
        {"name": "listCapabilities", "isasync": false, "params": []}
    ]})
}

async fn server_with_catalog() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(Command("listApis"))
        .respond_with(ok("listApis", catalog_body()))
        .mount(&server)
        .await;
    Mock::given(Command("listCapabilities"))
        .respond_with(ok(
            "listCapabilities",
            json!({"capability": {"cloudstackversion": "4.20.1.0"}}),
        ))
        .mount(&server)
        .await;
    server
}

fn builder(server: &MockServer) -> ClientBuilder {
    Client::builder(format!("{}/client/api", server.uri()))
        .api_key(KEY, SECRET)
        .poll_config(PollConfig {
            initial_interval: Duration::from_millis(5),
            max_interval: Duration::from_millis(20),
            multiplier: 2.0,
            timeout: Duration::from_secs(5),
        })
}

// ---- tests --------------------------------------------------------------------------------

#[tokio::test]
async fn discovers_and_calls_with_valid_signatures() {
    let server = server_with_catalog().await;
    Mock::given(Command("listZones"))
        .and(Signed { sha512: false })
        .and(HasParam("available", "true"))
        .and(HasParam("signatureversion", "3"))
        .respond_with(ok(
            "listZones",
            json!({"count": 1, "zone": [{"id": "z1", "name": "Zone ~1"}]}),
        ))
        .expect(2)
        .mount(&server)
        .await;

    for http_method in [HttpMethod::Post, HttpMethod::Get] {
        let client = builder(&server).http_method(http_method).build().unwrap();
        // verb/noun syntax and parameter-name case are resolved via the catalog
        let zones = client.request("list zones").param("Available", true).await.unwrap();
        assert_eq!(zones.command(), "listZones");
        assert_eq!(zones.items()[0]["name"], "Zone ~1");
        let catalog = client.cached_catalog().await.unwrap();
        assert_eq!(catalog.server_version(), Some("4.20.1.0"));
    }
}

#[tokio::test]
async fn signature_covers_values_with_tilde_and_maps() {
    let server = server_with_catalog().await;
    Mock::given(Command("deployVirtualMachine"))
        .and(Signed { sha512: false })
        .and(HasParam("displayname", "web ~ 01"))
        .and(HasParam("details[0].cpuNumber", "2"))
        .respond_with(ok("deployVirtualMachine", json!({"jobid": "j1", "id": "vm1"})))
        .expect(1)
        .mount(&server)
        .await;
    let client = builder(&server).http_method(HttpMethod::Get).build().unwrap();
    let resp = client
        .request("deployVirtualMachine")
        .param("zoneid", "z")
        .param("serviceofferingid", "s")
        .param("templateid", "t")
        .param("displayname", "web ~ 01")
        .param("details", ParamValue::map([("cpuNumber", "2")]))
        .no_wait()
        .await
        .unwrap();
    assert!(resp.is_pending());
    assert_eq!(resp.job().unwrap().job_id, "j1");
    assert_eq!(resp.job().unwrap().instance_id.as_deref(), Some("vm1"));
}

#[tokio::test]
async fn validation_happens_before_sending() {
    let server = server_with_catalog().await;
    Mock::given(Command("deployVirtualMachine"))
        .respond_with(ok("x", json!({})))
        .expect(0)
        .mount(&server)
        .await;
    let client = builder(&server).build().unwrap();

    let err = client
        .request("deployVirtualMachine")
        .param("zoneidd", "z")
        .await
        .unwrap_err();
    let Error::InvalidParams { api, problems } = err else {
        panic!("unexpected error")
    };
    assert_eq!(api, "deployVirtualMachine");
    assert!(problems.contains(&ParamProblem::Unknown {
        name: "zoneidd".into(),
        suggestions: vec!["zoneid".into()]
    }));
    assert!(problems.contains(&ParamProblem::Missing {
        name: "templateid".into()
    }));

    let err = client.request("deployVirtualMachin").await.unwrap_err();
    assert!(matches!(err, Error::UnknownApi { ref suggestions, .. } if suggestions[0] == "deployVirtualMachine"));
    assert!(err.to_string().contains("did you mean deployVirtualMachine"));
}

#[tokio::test]
async fn polls_async_jobs_until_done() {
    let server = server_with_catalog().await;
    Mock::given(Command("deployVirtualMachine"))
        .respond_with(ok("deployVirtualMachine", json!({"jobid": "job-1", "id": "vm-1"})))
        .mount(&server)
        .await;
    Mock::given(Command("queryAsyncJobResult"))
        .and(HasParam("jobid", "job-1"))
        .respond_with(ok("queryAsyncJobResult", json!({"jobid": "job-1", "jobstatus": 0})))
        .up_to_n_times(2)
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(Command("queryAsyncJobResult"))
        .and(HasParam("jobid", "job-1"))
        .respond_with(ok(
            "queryAsyncJobResult",
            json!({"jobid": "job-1", "jobstatus": 1, "jobresultcode": 0, "jobresulttype": "object",
                   "jobinstancetype": "VirtualMachine", "jobinstanceid": "vm-1",
                   "jobresult": {"virtualmachine": {"id": "vm-1", "state": "Running"}}}),
        ))
        .expect(1)
        .mount(&server)
        .await;

    let client = builder(&server).build().unwrap();
    let vm = client
        .request("deployVirtualMachine")
        .params([("zoneid", "z"), ("serviceofferingid", "s"), ("templateid", "t")])
        .await
        .unwrap();
    assert_eq!(vm.entity().unwrap()["state"], "Running");
    let job = vm.job().unwrap();
    assert_eq!(job.status, JobStatus::Succeeded);
    assert_eq!(job.instance_type.as_deref(), Some("VirtualMachine"));
}

#[tokio::test]
async fn failed_jobs_become_errors() {
    let server = server_with_catalog().await;
    Mock::given(Command("deployVirtualMachine"))
        .respond_with(ok("deployVirtualMachine", json!({"jobid": "job-2"})))
        .mount(&server)
        .await;
    Mock::given(Command("queryAsyncJobResult"))
        .respond_with(ok(
            "queryAsyncJobResult",
            json!({"jobid": "job-2", "jobstatus": 2, "jobresultcode": 530, "jobresulttype": "object",
                   "jobresult": {"errorcode": 533, "errortext": "Unable to create a deployment for VM"}}),
        ))
        .mount(&server)
        .await;
    let client = builder(&server).build().unwrap();
    let err = client
        .request("deployVirtualMachine")
        .params([("zoneid", "z"), ("serviceofferingid", "s"), ("templateid", "t")])
        .await
        .unwrap_err();
    match err {
        Error::JobFailed { job_id, error, .. } => {
            assert_eq!(job_id, "job-2");
            assert_eq!(error.error_code, Some(533));
            assert_eq!(error.error_text, "Unable to create a deployment for VM");
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn job_timeout() {
    let server = server_with_catalog().await;
    Mock::given(Command("queryAsyncJobResult"))
        .respond_with(ok("queryAsyncJobResult", json!({"jobid": "slow", "jobstatus": 0})))
        .mount(&server)
        .await;
    let client = builder(&server)
        .async_timeout(Duration::from_millis(60))
        .build()
        .unwrap();
    let err = client.wait_for_job("slow").await.unwrap_err();
    assert!(matches!(err, Error::JobTimeout { .. }));
}

#[tokio::test]
async fn server_errors_are_structured() {
    let server = server_with_catalog().await;
    Mock::given(Command("listZones"))
        .respond_with(ResponseTemplate::new(431).set_body_json(json!({"listzonesresponse": {
            "uuidList": [], "errorcode": 431, "cserrorcode": 9999, "errortext": "Unable to execute API command listzones due to invalid value"}})))
        .mount(&server)
        .await;
    let client = builder(&server).build().unwrap();
    let err = client.request("listZones").await.unwrap_err();
    let api = err.api_error().unwrap();
    assert_eq!(
        (api.http_status, api.error_code, api.cs_error_code),
        (431, Some(431), Some(9999))
    );
}

#[tokio::test]
async fn paginates() {
    let server = server_with_catalog().await;
    let vms: Vec<Value> = (0..5).map(|i| json!({"id": format!("vm{i}")})).collect();
    for (page, chunk) in vms.chunks(2).enumerate() {
        let page = (page + 1).to_string();
        Mock::given(Command("listVirtualMachines"))
            .and(HasParam("pagesize", "2"))
            .and(move |req: &Request| param(req, "page").as_deref() == Some(page.as_str()))
            .respond_with(ok("listVirtualMachines", json!({"count": 5, "virtualmachine": chunk})))
            .expect(1)
            .mount(&server)
            .await;
    }
    let client = builder(&server).build().unwrap();
    let items: Vec<Value> = client
        .request("listVirtualMachines")
        .items(2)
        .try_collect()
        .await
        .unwrap();
    let ids: Vec<&str> = items.iter().map(|v| v["id"].as_str().unwrap()).collect();
    assert_eq!(ids, ["vm0", "vm1", "vm2", "vm3", "vm4"]);
}

#[tokio::test]
async fn session_login_and_relogin() {
    let server = MockServer::start().await;
    let logins = Arc::new(AtomicUsize::new(0));
    let counter = logins.clone();
    Mock::given(method("POST"))
        .and(Command("login"))
        .and(HasParam("username", "admin"))
        .and(HasParam("domain", "/"))
        .respond_with(move |_: &Request| {
            let n = counter.fetch_add(1, Ordering::SeqCst) + 1;
            ResponseTemplate::new(200)
                .append_header("Set-Cookie", format!("JSESSIONID=js{n}; Path=/"))
                .set_body_json(json!({"loginresponse": {"sessionkey": format!("key{n}"), "username": "admin"}}))
        })
        .mount(&server)
        .await;
    // the first session "expires" after one call
    Mock::given(Command("listZones"))
        .and(HasParam("sessionkey", "key1"))
        .respond_with(ok("listZones", json!({"count": 1, "zone": [{"id": "z"}]})))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(Command("listZones"))
        .and(HasParam("sessionkey", "key1"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({"listzonesresponse": {
            "errorcode": 401, "errortext": "unable to verify user credentials"}})))
        .mount(&server)
        .await;
    Mock::given(Command("listZones"))
        .and(HasParam("sessionkey", "key2"))
        .and(|req: &Request| {
            req.headers
                .get("cookie")
                .is_some_and(|c| c.to_str().unwrap().contains("JSESSIONID=js2"))
        })
        .respond_with(ok("listZones", json!({"count": 1, "zone": [{"id": "z"}]})))
        .mount(&server)
        .await;

    let client = Client::builder(server.uri())
        .password("admin", "password", Some("/".into()))
        .discovery(Discovery::Disabled)
        .build()
        .unwrap();
    assert_eq!(client.request("listZones").await.unwrap().items().len(), 1);
    assert_eq!(client.request("listZones").await.unwrap().items().len(), 1);
    assert_eq!(logins.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn two_factor_login() {
    let server = MockServer::start().await;
    Mock::given(Command("login"))
        .respond_with(ok(
            "login",
            json!({"sessionkey": "k", "is2faenabled": "true", "is2faverified": "false"}),
        ))
        .mount(&server)
        .await;
    Mock::given(Command("validateUserTwoFactorAuthenticationCode"))
        .and(HasParam("codefor2fa", "123456"))
        .and(HasParam("sessionkey", "k"))
        .respond_with(ok("validateUserTwoFactorAuthenticationCode", json!({})))
        .expect(1)
        .mount(&server)
        .await;

    let without = Client::builder(server.uri())
        .password("u", "p", None)
        .discovery(Discovery::Disabled)
        .build()
        .unwrap();
    assert!(matches!(without.login().await, Err(Error::TwoFactorRequired)));

    let with = Client::builder(server.uri())
        .password("u", "p", None)
        .two_factor_provider(|| async { Ok("123456".to_owned()) })
        .discovery(Discovery::Disabled)
        .build()
        .unwrap();
    with.login().await.unwrap();
}

#[tokio::test]
async fn auto_signature_algorithm_falls_back_and_remembers() {
    let server = MockServer::start().await;
    let unauthorized = || {
        ResponseTemplate::new(401).set_body_json(json!({"errorresponse": {"errorcode": 401, "errortext": "unable to verify user credentials and/or request signature"}}))
    };
    Mock::given(Signed { sha512: false })
        .and(Command("listZones"))
        .respond_with(ok("listZones", json!({})))
        .expect(2)
        .mount(&server)
        .await;
    Mock::given(Signed { sha512: true })
        .respond_with(unauthorized())
        .expect(1)
        .mount(&server)
        .await;

    let client = builder(&server)
        .signature_algorithm(SignatureAlgorithm::Auto)
        .discovery(Discovery::Disabled)
        .build()
        .unwrap();
    client.request("listZones").await.unwrap();
    client.request("listZones").await.unwrap(); // goes straight to SHA1
}

#[tokio::test]
async fn sensitive_values_are_posted_in_auto_mode() {
    let server = server_with_catalog().await;
    Mock::given(method("POST"))
        .and(Command("deployVirtualMachine"))
        .and(Signed { sha512: false })
        .respond_with(ok("deployVirtualMachine", json!({"jobid": "j"})))
        .expect(1)
        .mount(&server)
        .await;
    let client = builder(&server).http_method(HttpMethod::Auto).build().unwrap();
    client
        .request("deployVirtualMachine")
        .params([
            ("zoneid", "z"),
            ("serviceofferingid", "s"),
            ("templateid", "t"),
            ("userdata", "I2Nsb3VkLWNvbmZpZw=="),
        ])
        .no_wait()
        .await
        .unwrap();
}

#[tokio::test]
async fn disk_cache_avoids_rediscovery() {
    let server = MockServer::start().await;
    Mock::given(Command("listApis"))
        .respond_with(ok("listApis", catalog_body()))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(Command("listCapabilities"))
        .respond_with(ok(
            "listCapabilities",
            json!({"capability": {"cloudstackversion": "4.22.0.0"}}),
        ))
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();

    for _ in 0..2 {
        let client = builder(&server)
            .discovery_cache(DiscoveryCache::new(dir.path()))
            .build()
            .unwrap();
        let catalog = client.catalog().await.unwrap();
        assert_eq!(catalog.len(), 5);
        assert_eq!(catalog.server_version(), Some("4.22.0.0"));
    }
    // a different identity does not reuse the cache entry
    let cache = DiscoveryCache::new(dir.path());
    assert_ne!(cache.path_for("e", "key:a"), cache.path_for("e", "key:b"));
}

#[tokio::test]
async fn works_without_discovery() {
    let server = MockServer::start().await;
    Mock::given(Command("listApis"))
        .respond_with(ok("listApis", catalog_body()))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(Command("startVirtualMachine"))
        .respond_with(ok("startVirtualMachine", json!({"jobid": "j9"})))
        .mount(&server)
        .await;
    Mock::given(Command("queryAsyncJobResult"))
        .respond_with(ok(
            "queryAsyncJobResult",
            json!({"jobid": "j9", "jobstatus": 1, "jobresult": {"virtualmachine": {"id": "v"}}}),
        ))
        .mount(&server)
        .await;
    let client = builder(&server)
        .discovery(Discovery::Disabled)
        .validation(Validation::Off)
        .build()
        .unwrap();
    let vm = client.request("startVirtualMachine").param("id", "v").await.unwrap();
    assert_eq!(vm.entity().unwrap()["id"], "v");
}
