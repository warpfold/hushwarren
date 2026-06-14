//! Captive-portal probe classification — zero-touch-ux.md §3 / §10 scenario 5.
//!
//! Simulates the hotel-Wi-Fi portal against a local mock HTTP server: the
//! probe must classify a 302 redirect AND a non-Success body as "portal",
//! classify Apple's Success sentinel as "clean", and treat network errors as
//! clean (P1: never go offline because a probe failed).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::{extract::State, response::IntoResponse, routing::get, Router};
use hush_daemon::sentinel::watch::probe_portal_at_url;

const APPLE_SUCCESS: &str = "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>";

#[derive(Clone)]
struct PortalState {
    portal_active: Arc<AtomicBool>,
}

async fn hotspot(State(s): State<PortalState>) -> axum::response::Response {
    if s.portal_active.load(Ordering::SeqCst) {
        // Typical portal behavior: redirect to the login page.
        (
            axum::http::StatusCode::FOUND,
            [("location", "http://portal.local/login")],
            "",
        )
            .into_response()
    } else {
        APPLE_SUCCESS.into_response()
    }
}

async fn start_mock(portal_active: Arc<AtomicBool>) -> SocketAddr {
    let app = Router::new()
        .route("/hotspot-detect.html", get(hotspot))
        .route(
            "/portal-body.html",
            get(|| async { "<html><body>Welcome to Hotel WiFi! Please log in.</body></html>" }),
        )
        .with_state(PortalState { portal_active });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

#[tokio::test]
async fn portal_redirect_detected_then_clears() {
    let portal = Arc::new(AtomicBool::new(true));
    let addr = start_mock(portal.clone()).await;
    let url = format!("http://{addr}/hotspot-detect.html");
    let t = Duration::from_secs(3);

    // Portal up: 302 ⇒ probe says "portal" (false = not clean).
    assert!(
        !probe_portal_at_url(&url, t).await,
        "302 redirect must classify as portal"
    );

    // User logged in: success body ⇒ probe says clean ⇒ Sentinel re-arms.
    portal.store(false, Ordering::SeqCst);
    assert!(
        probe_portal_at_url(&url, t).await,
        "Apple Success body must classify as clean"
    );
}

#[tokio::test]
async fn portal_interception_body_detected() {
    let addr = start_mock(Arc::new(AtomicBool::new(false))).await;
    // A portal that rewrites content instead of redirecting (NXDOMAIN-hijack
    // style): wrong body ⇒ portal.
    let url = format!("http://{addr}/portal-body.html");
    assert!(
        !probe_portal_at_url(&url, Duration::from_secs(3)).await,
        "non-Success body must classify as portal"
    );
}

#[tokio::test]
async fn probe_network_error_assumes_clean() {
    // Connection-refused (nothing listening): P1 rule — never conclude portal
    // (and thus never disarm filtering) from a probe transport failure.
    assert!(
        probe_portal_at_url(
            "http://127.0.0.1:1/hotspot-detect.html",
            Duration::from_secs(1)
        )
        .await,
        "network error must assume clean"
    );
}
