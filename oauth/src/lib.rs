#![warn(missing_docs)]
//! Provides a Spotify access token using either the OAuth authorization code
//! flow with PKCE, or the device authorization flow.
//!
//! Assuming sufficient scopes, the returned access token may be used with Spotify's
//! Web API, and/or to establish a new Session with [`librespot_core`].
//!
//! The authorization code flow ([`OAuthClient`]) is an interactive process which
//! requires a web browser to complete. The resulting code must then be provided back
//! from the browser to this library for exchange into an access token. Providing the
//! code can be automatic via a spawned http server (mimicking Spotify's client), or
//! manually via stdin. The latter is appropriate for headless systems.
//!
//! The device authorization flow ([`DeviceAuthClient`]) instead has Spotify issue a
//! short code which the user types in at <https://spotify.com/pair> from any other
//! device. Nothing has to listen on a port and no browser is needed on the machine
//! running librespot. Spotify only enables this flow for some client IDs; see
//! `docs/device-authorization.md`.

use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener},
    sync::mpsc,
    time::{Duration, Instant},
};

use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, CsrfToken, DeviceAuthorizationUrl, EmptyExtraTokenFields,
    EndpointNotSet, EndpointSet, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken,
    Scope, StandardDeviceAuthorizationResponse, StandardTokenResponse, TokenResponse, TokenUrl,
    basic::BasicClient, basic::BasicTokenType,
};

use log::{debug, error, info, trace, warn};
use thiserror::Error;
use url::Url;

// TLS Feature Validation
//
// These compile-time checks are placed in the oauth crate rather than core for a specific reason:
// oauth is at the bottom of the dependency tree (even librespot-core depends on librespot-oauth),
// which means it gets compiled first. This ensures TLS feature conflicts are detected early in
// the build process, providing immediate feedback to users rather than failing later during
// core compilation.
//
// The dependency chain is: workspace -> core -> oauth
// So oauth's feature validation runs before core's, catching configuration errors quickly.

#[cfg(all(feature = "native-tls", feature = "__rustls"))]
compile_error!(
    "Feature \"native-tls\" is mutually exclusive with \"rustls-tls-native-roots\" and \"rustls-tls-webpki-roots\". Enable only one."
);

#[cfg(not(any(feature = "native-tls", feature = "__rustls")))]
compile_error!(
    "Either feature \"native-tls\" (default), \"rustls-tls-native-roots\" or \"rustls-tls-webpki-roots\" must be enabled for this crate."
);

/// Spotify's authorization endpoint, for the authorization code flow.
const AUTH_URL: &str = "https://accounts.spotify.com/authorize";

/// Spotify's token endpoint, shared by every grant type in this crate.
const TOKEN_URL: &str = "https://accounts.spotify.com/api/token";

/// Spotify's device authorization endpoint.
const DEVICE_AUTHORIZATION_URL: &str = "https://accounts.spotify.com/oauth2/device/authorize";

/// A [`BasicClient`] configured for the device authorization flow.
///
/// The authorization endpoint is deliberately left unset: this flow never
/// redirects a user agent, so there is nothing to send them to.
type DeviceBasicClient =
    BasicClient<EndpointNotSet, EndpointSet, EndpointNotSet, EndpointNotSet, EndpointSet>;

/// Possible errors encountered during the OAuth authentication flow.
#[derive(Debug, Error)]
pub enum OAuthError {
    /// The redirect URI cannot be parsed as a valid URL.
    #[error("Unable to parse redirect URI {uri} ({e})")]
    AuthCodeBadUri {
        /// Auth URI.
        uri: String,
        /// Inner error code.
        e: url::ParseError,
    },

    /// The authorization code parameter is missing in the redirect URI.
    #[error("Auth code param not found in URI {uri}")]
    AuthCodeNotFound {
        /// Auth URI.
        uri: String,
    },

    /// Failed to read input from standard input when manually collecting auth code.
    #[error("Failed to read redirect URI from stdin")]
    AuthCodeStdinRead,

    /// Could not bind TCP listener to the specified socket address for OAuth callback.
    #[error("Failed to bind server to {addr} ({e})")]
    AuthCodeListenerBind {
        /// Callback address.
        addr: SocketAddr,
        /// Inner error code.
        e: io::Error,
    },

    /// Listener terminated before receiving an OAuth callback connection.
    #[error("Listener terminated without accepting a connection")]
    AuthCodeListenerTerminated,

    /// Failed to read incoming HTTP request containing OAuth callback.
    #[error("Failed to read redirect URI from HTTP request")]
    AuthCodeListenerRead,

    /// Received malformed HTTP request for OAuth callback.
    #[error("Failed to parse redirect URI from HTTP request")]
    AuthCodeListenerParse,

    /// Could not send HTTP response after handling OAuth callback.
    #[error("Failed to write HTTP response")]
    AuthCodeListenerWrite,

    /// Invalid Spotify authorization endpoint URL.
    #[error("Invalid Spotify OAuth URI")]
    InvalidSpotifyUri,

    /// Redirect URI failed validation.
    #[error("Invalid Redirect URI {uri} ({e})")]
    InvalidRedirectUri {
        /// Auth URI.
        uri: String,
        /// Inner error code
        e: url::ParseError,
    },

    /// Channel communication failure.
    #[error("Failed to receive code")]
    Recv,

    /// Token exchange failure with Spotify's authorization server.
    #[error("Failed to exchange code for access token ({e})")]
    ExchangeCode {
        /// Inner error description
        e: String,
    },

    /// Device code request failure with Spotify's authorization server.
    #[error("Failed to obtain device code ({e})")]
    DeviceCode {
        /// Inner error description
        e: String,
    },

    /// Token exchange failure, including the user declining or letting the code expire.
    #[error("Failed to exchange device code for access token ({e})")]
    ExchangeDeviceCode {
        /// Inner error description
        e: String,
    },
}

/// Represents an OAuth token used for accessing Spotify's Web API and sessions.
#[derive(Debug, Clone)]
pub struct OAuthToken {
    /// Bearer token used for authenticated Spotify API requests
    pub access_token: String,
    /// Long-lived token used to obtain new access tokens
    pub refresh_token: String,
    /// Instant when the access token becomes invalid
    pub expires_at: Instant,
    /// Type of token
    pub token_type: String,
    /// Permission scopes granted by this token
    pub scopes: Vec<String>,
}

/// Return code query-string parameter from the redirect URI.
fn get_code(redirect_url: &str) -> Result<AuthorizationCode, OAuthError> {
    let url = Url::parse(redirect_url).map_err(|e| OAuthError::AuthCodeBadUri {
        uri: redirect_url.to_string(),
        e,
    })?;
    let code = url
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, code)| AuthorizationCode::new(code.into_owned()))
        .ok_or(OAuthError::AuthCodeNotFound {
            uri: redirect_url.to_string(),
        })?;

    Ok(code)
}

/// Prompt for redirect URI on stdin and return auth code.
fn get_authcode_stdin() -> Result<AuthorizationCode, OAuthError> {
    println!("Provide redirect URL");
    let mut buffer = String::new();
    let stdin = io::stdin();
    stdin
        .read_line(&mut buffer)
        .map_err(|_| OAuthError::AuthCodeStdinRead)?;

    get_code(buffer.trim())
}

/// How long a single connection may stay silent before it is abandoned in
/// favour of the next one, so a browser that opens a socket without ever writing
/// to it cannot park the login.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Overall budget for the interactive login. Without it an abandoned login
/// blocks in `accept()` for the life of the process while still holding the
/// callback port, which no caller can recover from.
const AUTHCODE_LISTENER_TIMEOUT: Duration = Duration::from_secs(300);

/// How often to re-check the deadline while waiting for a connection.
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Blank lines tolerated before the request line on one connection.
const MAX_BLANK_LINES: usize = 8;

/// Cap on a single request line, so a peer that never sends a newline cannot
/// grow the read buffer without bound.
const MAX_REQUEST_LINE_BYTES: u64 = 8 * 1024;

/// Unusable connections tolerated before giving up, so a client that only ever
/// sends noise cannot hold the port open indefinitely.
const MAX_SKIPPED_REQUESTS: usize = 64;

const BAD_REQUEST_RESPONSE: &[u8] =
    b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nConnection: close\r\n\r\n";

/// Reader that refuses to keep reading once `deadline` has passed.
///
/// A socket read timeout applies per `recv` call, and one `read_line` issues as
/// many of those as it needs to reach a newline. A peer sending a byte at a time
/// therefore gets the full timeout back on every byte, and a single `read_line`
/// can outlive the overall deadline by roughly timeout times the byte cap.
/// Checking here bounds the whole read rather than each syscall inside it.
struct DeadlineReader<R> {
    inner: R,
    deadline: Instant,
}

impl<R: Read> Read for DeadlineReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "OAuth callback deadline reached",
            ));
        }
        self.inner.read(buf)
    }
}

/// Read the request line from `reader`, skipping any blank lines that precede it.
///
/// Returns `None` when the peer closed the connection, timed out, or sent nothing
/// but blank lines.
///
/// The blank lines are skipped *within* a connection, not by moving on to the
/// next one. RFC 9112 section 2.2 requires a server to tolerate a CRLF received
/// before the request line, and at least some browsers send one, so the blank
/// line and the request that carries the code can arrive on the same connection.
/// Abandoning the connection on a blank line would discard the code and then
/// block forever waiting for a redirect that has already been delivered.
///
/// Time is bounded by the caller wrapping `reader` in a [`DeadlineReader`]: no
/// new read starts once the login deadline has passed, so the overshoot is at
/// most one already-running read, capped by the socket read timeout.
fn read_request_line(reader: &mut impl BufRead) -> Option<String> {
    // MAX_BLANK_LINES blanks plus the request line that follows them.
    for _ in 0..=MAX_BLANK_LINES {
        let mut line = String::new();
        match reader.take(MAX_REQUEST_LINE_BYTES).read_line(&mut line) {
            // Connection closed without sending a request.
            Ok(0) => return None,
            Ok(_) if line.trim().is_empty() => continue,
            Ok(_) => return Some(line),
            Err(e) => {
                debug!("OAuth callback read error, moving to the next connection: {e}");
                return None;
            }
        }
    }
    None
}

/// Spawn HTTP server at provided socket address to accept OAuth callback and return auth code.
fn get_authcode_listener(
    socket_address: SocketAddr,
    message: String,
) -> Result<AuthorizationCode, OAuthError> {
    let listener =
        TcpListener::bind(socket_address).map_err(|e| OAuthError::AuthCodeListenerBind {
            addr: socket_address,
            e,
        })?;
    // Non-blocking so the accept loop can honour AUTHCODE_LISTENER_TIMEOUT
    // instead of parking in accept() forever.
    listener
        .set_nonblocking(true)
        .map_err(|e| OAuthError::AuthCodeListenerBind {
            addr: socket_address,
            e,
        })?;
    info!("OAuth server listening on {socket_address:?}");

    accept_authcode(&listener, message)
}

/// Accept connections until one carries the authorization code.
///
/// Anything a browser may send before the redirect is skipped rather than
/// mistaken for the callback: a bare CRLF, a connection opened and closed without
/// a request, or an unrelated request such as `/favicon.ico`. Treating any of
/// those as the callback returns an error, which drops the listener and closes
/// the port, so the redirect that actually carries the code arrives at a dead
/// port and the user is stranded on a browser "unable to connect" page with no
/// way to recover. See librespot-org/librespot#1705.
///
/// `listener` must already be non-blocking. Split out from
/// `get_authcode_listener` so tests can supply a listener bound to port 0 rather
/// than racing for a fixed port.
fn accept_authcode(
    listener: &TcpListener,
    message: String,
) -> Result<AuthorizationCode, OAuthError> {
    let deadline = Instant::now() + AUTHCODE_LISTENER_TIMEOUT;
    let mut skipped = 0usize;

    // Counts one unusable connection. Returns Err once too many pile up, so a
    // client that only ever sends noise cannot hold the port open. Checked here
    // rather than at the top of the loop so we never block in accept() for a
    // connection we have already decided to reject.
    macro_rules! skip_connection {
        () => {{
            skipped += 1;
            if skipped >= MAX_SKIPPED_REQUESTS {
                warn!("OAuth callback: too many unusable requests, giving up");
                return Err(OAuthError::AuthCodeListenerTerminated);
            }
            continue;
        }};
    }

    loop {
        if Instant::now() >= deadline {
            warn!("OAuth callback: no authorization code received before the deadline");
            return Err(OAuthError::AuthCodeListenerTerminated);
        }

        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL_INTERVAL);
                continue;
            }
            Err(e) => {
                debug!("OAuth callback accept error, still listening: {e}");
                skip_connection!()
            }
        };

        // An accepted socket may inherit the listener's non-blocking mode, and
        // the reads below are blocking by design (bounded by the read timeout).
        if let Err(e) = stream.set_nonblocking(false) {
            debug!("OAuth callback: cannot make connection blocking ({e}), skipping");
            skip_connection!()
        }
        // Refuse to read from a connection we cannot bound, rather than risk
        // blocking on it forever. Capped by the remaining overall budget so a
        // late connection cannot read past the deadline.
        let read_budget = REQUEST_READ_TIMEOUT
            .min(deadline.saturating_duration_since(Instant::now()))
            .max(Duration::from_millis(1));
        if let Err(e) = stream.set_read_timeout(Some(read_budget)) {
            debug!("OAuth callback: cannot bound reads on this connection ({e}), skipping");
            skip_connection!()
        }

        // Exactly one request per connection. Reading a second would mean
        // framing the first (Content-Length, chunked encoding) to know where it
        // ends, and getting that wrong loses the code, which is the very bug
        // this function exists to avoid. Nothing is given up by not doing it:
        // browsers do not pipeline, and the 400 below closes the connection, so
        // a browser with more to say opens a new one and we accept that instead.
        // The socket timeout bounds one recv; the DeadlineReader stops new reads
        // past the deadline, so a peer dribbling bytes cannot win the timeout
        // back on every byte and stretch one read_line far beyond the budget.
        let mut reader = BufReader::new(DeadlineReader {
            inner: &stream,
            deadline,
        });
        let Some(request_line) = read_request_line(&mut reader) else {
            debug!("OAuth callback: no request line, still listening");
            skip_connection!()
        };

        let Some(redirect_url) = request_line.split_whitespace().nth(1) else {
            debug!("OAuth callback: unparseable request line, still listening");
            let _ = (&stream).write_all(BAD_REQUEST_RESPONSE);
            skip_connection!()
        };

        let code = match get_code(&("http://localhost".to_string() + redirect_url)) {
            Ok(code) => code,
            // Browser noise (`/favicon.ico`, `/`, a pre-flight). Answer it so the
            // browser is not left hanging, then wait for the real redirect.
            Err(e) => {
                debug!("OAuth callback: request carried no code ({e}), still listening");
                let _ = (&stream).write_all(BAD_REQUEST_RESPONSE);
                skip_connection!()
            }
        };

        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nConnection: close\r\n\r\n{}",
            message.len(),
            message
        );
        // Best effort. The code is already in hand, so a browser that hung up
        // before reading the page must not cost the user the login.
        if let Err(e) = (&stream).write_all(response.as_bytes()) {
            debug!("OAuth callback: could not write the success page ({e})");
        }

        return Ok(code);
    }
}

// If the specified `redirect_uri` is HTTP and contains a port,
// then the corresponding socket address is returned.
fn get_socket_address(redirect_uri: &str) -> Option<SocketAddr> {
    let url = match Url::parse(redirect_uri) {
        Ok(u) if u.scheme() == "http" && u.port().is_some() => u,
        _ => return None,
    };
    match url.socket_addrs(|| None) {
        Ok(mut addrs) => addrs.pop(),
        _ => None,
    }
}

/// Struct that handle obtaining and refreshing access tokens.
pub struct OAuthClient {
    scopes: Vec<String>,
    redirect_uri: String,
    should_open_url: bool,
    message: String,
    client: BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointSet>,
}

/// Convert a token endpoint response into an [`OAuthToken`].
///
/// `default_scopes` stands in for the granted scopes when Spotify omits them
/// from the response.
fn build_token(
    resp: StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
    default_scopes: &[String],
) -> OAuthToken {
    trace!("Obtained new access token: {resp:?}");

    let token_scopes: Vec<String> = match resp.scopes() {
        Some(s) => s.iter().map(|s| s.to_string()).collect(),
        _ => default_scopes.to_vec(),
    };
    let refresh_token = match resp.refresh_token() {
        Some(t) => t.secret().to_string(),
        _ => "".to_string(), // Spotify always provides a refresh token.
    };
    OAuthToken {
        access_token: resp.access_token().secret().to_string(),
        refresh_token,
        expires_at: Instant::now()
            + resp
                .expires_in()
                .unwrap_or_else(|| Duration::from_secs(3600)),
        token_type: format!("{:?}", resp.token_type()),
        scopes: token_scopes,
    }
}

impl OAuthClient {
    /// Generates and opens/shows the authorization URL to obtain an access token.
    ///
    /// Returns a verifier that must be included in the final request for validation.
    fn set_auth_url(&self) -> PkceCodeVerifier {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        // Generate the full authorization URL.
        // Some of these scopes are unavailable for custom client IDs. Which?
        let request_scopes: Vec<oauth2::Scope> =
            self.scopes.iter().map(|s| Scope::new(s.into())).collect();
        let (auth_url, _) = self
            .client
            .authorize_url(CsrfToken::new_random)
            .add_scopes(request_scopes)
            .set_pkce_challenge(pkce_challenge)
            .url();

        if self.should_open_url {
            open::that_in_background(auth_url.as_str());
        }
        println!("Browse to: {auth_url}");

        pkce_verifier
    }

    fn build_token(
        &self,
        resp: StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
    ) -> Result<OAuthToken, OAuthError> {
        Ok(build_token(resp, &self.scopes))
    }

    /// Syncronously obtain a Spotify access token using the authorization code with PKCE OAuth flow.
    pub fn get_access_token(&self) -> Result<OAuthToken, OAuthError> {
        let pkce_verifier = self.set_auth_url();

        let code = match get_socket_address(&self.redirect_uri) {
            Some(addr) => get_authcode_listener(addr, self.message.clone()),
            _ => get_authcode_stdin(),
        }?;
        trace!("Exchange {code:?} for access token");

        let (tx, rx) = mpsc::channel();
        let client = self.client.clone();
        std::thread::spawn(move || {
            let http_client = reqwest::blocking::Client::new();
            let resp = client
                .exchange_code(code)
                .set_pkce_verifier(pkce_verifier)
                .request(&http_client);
            if let Err(e) = tx.send(resp) {
                error!("OAuth channel send error: {e}");
            }
        });
        let channel_response = rx.recv().map_err(|_| OAuthError::Recv)?;
        let token_response =
            channel_response.map_err(|e| OAuthError::ExchangeCode { e: e.to_string() })?;

        self.build_token(token_response)
    }

    /// Synchronously obtain a new valid OAuth token from `refresh_token`
    pub fn refresh_token(&self, refresh_token: &str) -> Result<OAuthToken, OAuthError> {
        let refresh_token = RefreshToken::new(refresh_token.to_string());
        let http_client = reqwest::blocking::Client::new();
        let resp = self
            .client
            .exchange_refresh_token(&refresh_token)
            .request(&http_client);

        let resp = resp.map_err(|e| OAuthError::ExchangeCode { e: e.to_string() })?;
        self.build_token(resp)
    }

    /// Asyncronously obtain a Spotify access token using the authorization code with PKCE OAuth flow.
    pub async fn get_access_token_async(&self) -> Result<OAuthToken, OAuthError> {
        let pkce_verifier = self.set_auth_url();

        let code = match get_socket_address(&self.redirect_uri) {
            Some(addr) => get_authcode_listener(addr, self.message.clone()),
            _ => get_authcode_stdin(),
        }?;
        trace!("Exchange {code:?} for access token");

        let http_client = reqwest::Client::new();
        let resp = self
            .client
            .exchange_code(code)
            .set_pkce_verifier(pkce_verifier)
            .request_async(&http_client)
            .await;

        let resp = resp.map_err(|e| OAuthError::ExchangeCode { e: e.to_string() })?;
        self.build_token(resp)
    }

    /// Asynchronously obtain a new valid OAuth token from `refresh_token`
    pub async fn refresh_token_async(&self, refresh_token: &str) -> Result<OAuthToken, OAuthError> {
        let refresh_token = RefreshToken::new(refresh_token.to_string());
        let http_client = reqwest::Client::new();
        let resp = self
            .client
            .exchange_refresh_token(&refresh_token)
            .request_async(&http_client)
            .await;

        let resp = resp.map_err(|e| OAuthError::ExchangeCode { e: e.to_string() })?;
        self.build_token(resp)
    }
}

/// Builder struct through which structures of type OAuthClient are instantiated.
pub struct OAuthClientBuilder {
    client_id: String,
    redirect_uri: String,
    scopes: Vec<String>,
    should_open_url: bool,
    message: String,
}

impl OAuthClientBuilder {
    /// Create a new OAuthClientBuilder with provided params and default config.
    ///
    /// `redirect_uri` must match to the registered Uris of `client_id`
    pub fn new(client_id: &str, redirect_uri: &str, scopes: Vec<&str>) -> Self {
        Self {
            client_id: client_id.to_string(),
            redirect_uri: redirect_uri.to_string(),
            scopes: scopes.into_iter().map(Into::into).collect(),
            should_open_url: false,
            message: String::from("Go back to your terminal :)"),
        }
    }

    /// When this function is added to the building process pipeline, the auth url will be
    /// opened with the default web browser. Otherwise, it will be printed to standard output.
    pub fn open_in_browser(mut self) -> Self {
        self.should_open_url = true;
        self
    }

    /// When this function is added to the building process pipeline, the body of the response to
    /// the callback request will be `message`. This is useful to load custom HTMLs to that &str.
    pub fn with_custom_message(mut self, message: &str) -> Self {
        self.message = message.to_string();
        self
    }

    /// End of the building process pipeline. If Ok, a OAuthClient instance will be returned.
    pub fn build(self) -> Result<OAuthClient, OAuthError> {
        let auth_url =
            AuthUrl::new(AUTH_URL.to_string()).map_err(|_| OAuthError::InvalidSpotifyUri)?;
        let token_url =
            TokenUrl::new(TOKEN_URL.to_string()).map_err(|_| OAuthError::InvalidSpotifyUri)?;
        let redirect_url = RedirectUrl::new(self.redirect_uri.clone()).map_err(|e| {
            OAuthError::InvalidRedirectUri {
                uri: self.redirect_uri.clone(),
                e,
            }
        })?;

        let client = BasicClient::new(ClientId::new(self.client_id.to_string()))
            .set_auth_uri(auth_url)
            .set_token_uri(token_url)
            .set_redirect_uri(redirect_url);

        Ok(OAuthClient {
            scopes: self.scopes,
            should_open_url: self.should_open_url,
            message: self.message,
            redirect_uri: self.redirect_uri,
            client,
        })
    }
}

/// Obtain a Spotify access token using the authorization code with PKCE OAuth flow.
/// The `redirect_uri` must match what is registered to the client ID.
#[deprecated(
    since = "0.7.0",
    note = "please use builder pattern with `OAuthClientBuilder` instead"
)]
/// Obtain a Spotify access token using the authorization code with PKCE OAuth flow.
/// The redirect_uri must match what is registered to the client ID.
pub fn get_access_token(
    client_id: &str,
    redirect_uri: &str,
    scopes: Vec<&str>,
) -> Result<OAuthToken, OAuthError> {
    let auth_url = AuthUrl::new(AUTH_URL.to_string()).map_err(|_| OAuthError::InvalidSpotifyUri)?;
    let token_url =
        TokenUrl::new(TOKEN_URL.to_string()).map_err(|_| OAuthError::InvalidSpotifyUri)?;
    let redirect_url =
        RedirectUrl::new(redirect_uri.to_string()).map_err(|e| OAuthError::InvalidRedirectUri {
            uri: redirect_uri.to_string(),
            e,
        })?;
    let client = BasicClient::new(ClientId::new(client_id.to_string()))
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_redirect_uri(redirect_url);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // Generate the full authorization URL.
    // Some of these scopes are unavailable for custom client IDs. Which?
    let request_scopes: Vec<oauth2::Scope> = scopes
        .clone()
        .into_iter()
        .map(|s| Scope::new(s.into()))
        .collect();
    let (auth_url, _) = client
        .authorize_url(CsrfToken::new_random)
        .add_scopes(request_scopes)
        .set_pkce_challenge(pkce_challenge)
        .url();

    println!("Browse to: {auth_url}");

    let code = match get_socket_address(redirect_uri) {
        Some(addr) => get_authcode_listener(addr, String::from("Go back to your terminal :)")),
        _ => get_authcode_stdin(),
    }?;
    trace!("Exchange {code:?} for access token");

    // Do this sync in another thread because I am too stupid to make the async version work.
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let http_client = reqwest::blocking::Client::new();
        let resp = client
            .exchange_code(code)
            .set_pkce_verifier(pkce_verifier)
            .request(&http_client);
        if let Err(e) = tx.send(resp) {
            error!("OAuth channel send error: {e}");
        }
    });
    let token_response = rx.recv().map_err(|_| OAuthError::Recv)?;
    let token = token_response.map_err(|e| OAuthError::ExchangeCode { e: e.to_string() })?;
    trace!("Obtained new access token: {token:?}");

    let token_scopes: Vec<String> = match token.scopes() {
        Some(s) => s.iter().map(|s| s.to_string()).collect(),
        _ => scopes.into_iter().map(Into::into).collect(),
    };
    let refresh_token = match token.refresh_token() {
        Some(t) => t.secret().to_string(),
        _ => "".to_string(), // Spotify always provides a refresh token.
    };
    Ok(OAuthToken {
        access_token: token.access_token().secret().to_string(),
        refresh_token,
        expires_at: Instant::now()
            + token
                .expires_in()
                .unwrap_or_else(|| Duration::from_secs(3600)),
        token_type: format!("{:?}", token.token_type()).to_string(), // Urgh!?
        scopes: token_scopes,
    })
}

/// A pending device authorization, waiting on the user's approval.
///
/// Show [`Self::url`] and [`Self::user_code`] to the user, then hand this to
/// [`DeviceAuthClient::poll_for_token`].
#[derive(Debug, Clone)]
pub struct DeviceAuthorization {
    inner: StandardDeviceAuthorizationResponse,
}

impl DeviceAuthorization {
    /// The code the user types in at [`Self::verification_uri`].
    pub fn user_code(&self) -> &str {
        self.inner.user_code().secret()
    }

    /// The page the user visits to enter [`Self::user_code`].
    pub fn verification_uri(&self) -> &str {
        self.inner.verification_uri().as_str()
    }

    /// [`Self::verification_uri`] with the code already filled in, when Spotify
    /// provides it.
    pub fn verification_uri_complete(&self) -> Option<&str> {
        self.inner
            .verification_uri_complete()
            .map(|uri| uri.secret().as_str())
    }

    /// The URL to send the user to, preferring the prefilled variant.
    pub fn url(&self) -> &str {
        self.verification_uri_complete()
            .unwrap_or_else(|| self.verification_uri())
    }
}

/// Struct that handles obtaining and refreshing access tokens by pairing a code.
///
/// Unlike [`OAuthClient`] this needs no redirect URI, nothing listening on a port,
/// and no browser on the machine running it. Spotify only enables this flow for
/// some client IDs; see `docs/device-authorization.md`.
pub struct DeviceAuthClient {
    scopes: Vec<String>,
    should_open_url: bool,
    client: DeviceBasicClient,
}

impl DeviceAuthClient {
    fn request_scopes(&self) -> Vec<Scope> {
        self.scopes.iter().map(|s| Scope::new(s.into())).collect()
    }

    /// Shows the user where to approve the authorization, opening it for them if
    /// the client was built with [`DeviceAuthClientBuilder::open_in_browser`].
    fn announce(&self, auth: &DeviceAuthorization) {
        let url = auth.url();
        if self.should_open_url {
            open::that_in_background(url);
        }
        println!("Browse to: {url}");
        println!("If prompted, enter code: {}", auth.user_code());
    }

    /// Synchronously request a device code for the user to approve
    pub fn request_device_code(&self) -> Result<DeviceAuthorization, OAuthError> {
        let http_client = reqwest::blocking::Client::new();
        let inner = self
            .client
            .exchange_device_code()
            .add_scopes(self.request_scopes())
            .request(&http_client)
            .map_err(|e| OAuthError::DeviceCode { e: e.to_string() })?;

        trace!("Obtained device authorization: {inner:?}");
        Ok(DeviceAuthorization { inner })
    }

    /// Synchronously poll Spotify until the user resolves `auth`
    ///
    /// Blocks until the user approves or declines, or the authorization expires.
    /// Spotify's requested poll interval and any `slow_down` it sends back are
    /// both respected.
    pub fn poll_for_token(&self, auth: &DeviceAuthorization) -> Result<OAuthToken, OAuthError> {
        let http_client = reqwest::blocking::Client::new();
        let resp = self
            .client
            .exchange_device_access_token(&auth.inner)
            .request(&http_client, std::thread::sleep, None)
            .map_err(|e| OAuthError::ExchangeDeviceCode { e: e.to_string() })?;

        Ok(build_token(resp, &self.scopes))
    }

    /// Synchronously obtain a Spotify access token using the device authorization flow.
    ///
    /// Requests a code, shows it to the user, then blocks until they approve it.
    /// Drive [`Self::request_device_code`] and [`Self::poll_for_token`] directly
    /// to present the code some other way.
    pub fn get_access_token(&self) -> Result<OAuthToken, OAuthError> {
        let auth = self.request_device_code()?;
        self.announce(&auth);
        self.poll_for_token(&auth)
    }

    /// Synchronously obtain a new valid OAuth token from `refresh_token`
    pub fn refresh_token(&self, refresh_token: &str) -> Result<OAuthToken, OAuthError> {
        let refresh_token = RefreshToken::new(refresh_token.to_string());
        let http_client = reqwest::blocking::Client::new();
        let resp = self
            .client
            .exchange_refresh_token(&refresh_token)
            .request(&http_client)
            .map_err(|e| OAuthError::ExchangeCode { e: e.to_string() })?;

        Ok(build_token(resp, &self.scopes))
    }

    /// Asynchronously request a device code for the user to approve
    pub async fn request_device_code_async(&self) -> Result<DeviceAuthorization, OAuthError> {
        let http_client = reqwest::Client::new();
        let inner = self
            .client
            .exchange_device_code()
            .add_scopes(self.request_scopes())
            .request_async(&http_client)
            .await
            .map_err(|e| OAuthError::DeviceCode { e: e.to_string() })?;

        trace!("Obtained device authorization: {inner:?}");
        Ok(DeviceAuthorization { inner })
    }

    /// Asynchronously poll Spotify until the user resolves `auth`
    ///
    /// See [`Self::poll_for_token`].
    pub async fn poll_for_token_async(
        &self,
        auth: &DeviceAuthorization,
    ) -> Result<OAuthToken, OAuthError> {
        let http_client = reqwest::Client::new();
        let resp = self
            .client
            .exchange_device_access_token(&auth.inner)
            .request_async(&http_client, tokio::time::sleep, None)
            .await
            .map_err(|e| OAuthError::ExchangeDeviceCode { e: e.to_string() })?;

        Ok(build_token(resp, &self.scopes))
    }

    /// Asynchronously obtain a Spotify access token using the device authorization flow.
    ///
    /// See [`Self::get_access_token`].
    pub async fn get_access_token_async(&self) -> Result<OAuthToken, OAuthError> {
        let auth = self.request_device_code_async().await?;
        self.announce(&auth);
        self.poll_for_token_async(&auth).await
    }

    /// Asynchronously obtain a new valid OAuth token from `refresh_token`
    pub async fn refresh_token_async(&self, refresh_token: &str) -> Result<OAuthToken, OAuthError> {
        let refresh_token = RefreshToken::new(refresh_token.to_string());
        let http_client = reqwest::Client::new();
        let resp = self
            .client
            .exchange_refresh_token(&refresh_token)
            .request_async(&http_client)
            .await
            .map_err(|e| OAuthError::ExchangeCode { e: e.to_string() })?;

        Ok(build_token(resp, &self.scopes))
    }
}

/// Builder struct through which structures of type DeviceAuthClient are instantiated.
pub struct DeviceAuthClientBuilder {
    client_id: String,
    scopes: Vec<String>,
    should_open_url: bool,
}

impl DeviceAuthClientBuilder {
    /// Create a new DeviceAuthClientBuilder with provided params and default config.
    ///
    /// Spotify fails the whole request with `invalid_scope` if it does not
    /// recognise any one of `scopes`, so unsupported scopes cannot be discovered
    /// by asking for extras and seeing what comes back.
    pub fn new(client_id: &str, scopes: Vec<&str>) -> Self {
        Self {
            client_id: client_id.to_string(),
            scopes: scopes.into_iter().map(Into::into).collect(),
            should_open_url: false,
        }
    }

    /// When this function is added to the building process pipeline, the verification
    /// url will also be opened with the default web browser. Otherwise, it is only
    /// printed to standard output.
    ///
    /// Off by default, since the point of this flow is that the device running
    /// librespot need not have a browser at all.
    pub fn open_in_browser(mut self) -> Self {
        self.should_open_url = true;
        self
    }

    /// End of the building process pipeline. If Ok, a DeviceAuthClient instance will be returned.
    pub fn build(self) -> Result<DeviceAuthClient, OAuthError> {
        let device_authorization_url =
            DeviceAuthorizationUrl::new(DEVICE_AUTHORIZATION_URL.to_string())
                .map_err(|_| OAuthError::InvalidSpotifyUri)?;
        let token_url =
            TokenUrl::new(TOKEN_URL.to_string()).map_err(|_| OAuthError::InvalidSpotifyUri)?;

        let client = BasicClient::new(ClientId::new(self.client_id))
            .set_token_uri(token_url)
            .set_device_authorization_url(device_authorization_url);

        Ok(DeviceAuthClient {
            scopes: self.scopes,
            should_open_url: self.should_open_url,
            client,
        })
    }
}

#[cfg(test)]
mod test {
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};

    use super::*;

    const CODE_REQUEST: &str = "GET /login?code=testcode123 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";

    /// Far enough out that the deadline never fires during a unit test.
    fn test_deadline() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    /// A reader that hands back one byte per call, standing in for a peer that
    /// dribbles bytes to win the socket timeout back on every one of them.
    struct DribbleReader {
        remaining: usize,
    }

    impl Read for DribbleReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.remaining == 0 || buf.is_empty() {
                return Ok(0);
            }
            self.remaining -= 1;
            buf[0] = b'x';
            Ok(1)
        }
    }

    #[test]
    fn deadline_reader_passes_reads_through_before_the_deadline() {
        let mut reader = DeadlineReader {
            inner: Cursor::new(b"hello".to_vec()),
            deadline: test_deadline(),
        };
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).expect("read before deadline");
        assert_eq!(buf, b"hello");
    }

    /// The bound has to sit at the read layer. A socket read timeout applies per
    /// recv, so one read_line over a dribbling peer would otherwise run for
    /// timeout times the byte cap regardless of the overall deadline.
    #[test]
    fn deadline_reader_stops_a_dribbling_peer_mid_line() {
        let mut reader = BufReader::new(DeadlineReader {
            // Never sends a newline, so read_line would keep asking for more.
            inner: DribbleReader {
                remaining: usize::MAX,
            },
            deadline: Instant::now(),
        });
        assert!(
            read_request_line(&mut reader).is_none(),
            "an expired deadline must end the read rather than accumulate bytes"
        );
    }

    /// Drive `accept_authcode` against a listener on port 0 while `client` talks
    /// to it, and return whatever the server resolved.
    ///
    /// The server runs on its own thread behind a watchdog so a regression that
    /// stops the loop from terminating fails the test instead of hanging the
    /// whole suite.
    fn run_listener(
        client: impl FnOnce(SocketAddr) + Send + 'static,
    ) -> Result<AuthorizationCode, OAuthError> {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        listener
            .set_nonblocking(true)
            .expect("accept_authcode requires a non-blocking listener");
        let addr = listener.local_addr().expect("local addr");

        let client_handle = std::thread::spawn(move || client(addr));
        let (tx, rx) = mpsc::channel();
        let server_handle =
            std::thread::spawn(move || tx.send(accept_authcode(&listener, "done".to_string())));

        let result = rx
            .recv_timeout(Duration::from_secs(30))
            .expect("listener did not finish within the watchdog window");
        client_handle.join().expect("client thread panicked");
        server_handle.join().expect("server thread panicked").ok();
        result
    }

    fn send(addr: SocketAddr, bytes: &[u8]) -> TcpStream {
        let mut stream = TcpStream::connect(addr).expect("connect");
        stream.write_all(bytes).expect("write");
        stream.flush().expect("flush");
        stream
    }

    #[test]
    fn request_line_read_past_leading_blank_lines() {
        let mut reader = Cursor::new(format!("\r\n\r\n{CODE_REQUEST}").into_bytes());
        let line = read_request_line(&mut reader).expect("should find the request line");
        assert!(
            line.starts_with("GET /login?code=testcode123"),
            "got: {line:?}"
        );
    }

    #[test]
    fn request_line_none_when_peer_sends_nothing() {
        let mut reader = Cursor::new(Vec::new());
        assert!(read_request_line(&mut reader).is_none());
    }

    #[test]
    fn request_line_none_when_only_blank_lines() {
        let mut reader = Cursor::new("\r\n".repeat(MAX_BLANK_LINES + 4).into_bytes());
        assert!(read_request_line(&mut reader).is_none());
    }

    /// The constant means what it says: MAX_BLANK_LINES blanks still leave the
    /// request line behind them readable.
    #[test]
    fn request_line_found_after_exactly_max_blank_lines() {
        let blanks = "\r\n".repeat(MAX_BLANK_LINES);
        let mut reader = Cursor::new(format!("{blanks}{CODE_REQUEST}").into_bytes());
        let line = read_request_line(&mut reader).expect("should find the request line");
        assert!(
            line.starts_with("GET /login?code=testcode123"),
            "got: {line:?}"
        );
    }

    /// A peer that never sends a newline must not grow the buffer without bound.
    #[test]
    fn request_line_is_length_capped() {
        let flood = "x".repeat((MAX_REQUEST_LINE_BYTES as usize) * 2);
        let mut reader = Cursor::new(flood.into_bytes());
        let line = read_request_line(&mut reader).expect("capped read still yields a line");
        assert_eq!(line.len(), MAX_REQUEST_LINE_BYTES as usize);
    }

    /// The librespot#1705 case as a *leading CRLF on the same connection*.
    /// Skipping to the next connection here would discard the code and hang.
    #[test]
    fn blank_line_before_code_on_same_connection() {
        let code = run_listener(|addr| {
            let _stream = send(addr, format!("\r\n{CODE_REQUEST}").as_bytes());
        })
        .expect("should recover the code");
        assert_eq!(code.secret(), "testcode123");
    }

    /// The librespot#1705 case as a *separate, dataless connection*.
    #[test]
    fn blank_connection_before_code_on_next_connection() {
        let code = run_listener(|addr| {
            drop(TcpStream::connect(addr).expect("connect"));
            let _stream = send(addr, CODE_REQUEST.as_bytes());
        })
        .expect("should recover the code");
        assert_eq!(code.secret(), "testcode123");
    }

    /// A parseable request that simply is not the callback must not end the flow.
    #[test]
    fn favicon_request_before_code_is_skipped() {
        let code = run_listener(|addr| {
            let _noise = send(
                addr,
                b"GET /favicon.ico HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            );
            let _stream = send(addr, CODE_REQUEST.as_bytes());
        })
        .expect("should recover the code");
        assert_eq!(code.secret(), "testcode123");
    }

    /// A browser that hangs up before reading the success page has still handed
    /// over a valid code, and losing it would cost the user the whole login.
    #[test]
    fn code_survives_a_browser_that_closes_before_the_response() {
        let code = run_listener(|addr| {
            let mut stream = TcpStream::connect(addr).expect("connect");
            stream.write_all(CODE_REQUEST.as_bytes()).expect("write");
            stream.flush().expect("flush");
            // Gone before the server can write the page back.
            let _ = stream.shutdown(std::net::Shutdown::Both);
        })
        .expect("code should survive a failed response write");
        assert_eq!(code.secret(), "testcode123");
    }

    #[test]
    fn gives_up_after_too_many_unusable_requests() {
        let result = run_listener(|addr| {
            for _ in 0..(MAX_SKIPPED_REQUESTS + 1) {
                // Once the server gives up the port is gone, so a refused
                // connection here is the expected end state, not a failure.
                if let Ok(stream) = TcpStream::connect(addr) {
                    drop(stream);
                }
            }
        });
        assert!(matches!(
            result,
            Err(OAuthError::AuthCodeListenerTerminated)
        ));
    }

    #[test]
    fn get_socket_address_none() {
        // No port
        assert_eq!(get_socket_address("http://127.0.0.1/foo"), None);
        assert_eq!(get_socket_address("http://127.0.0.1:/foo"), None);
        assert_eq!(get_socket_address("http://[::1]/foo"), None);
        // Not http
        assert_eq!(get_socket_address("https://127.0.0.1/foo"), None);
    }

    #[test]
    fn get_socket_address_some() {
        let localhost_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1234);
        let localhost_v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 8888);
        let addr_v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 1234);
        let addr_v6 = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
            8888,
        );

        // Loopback addresses
        assert_eq!(
            get_socket_address("http://127.0.0.1:1234/foo"),
            Some(localhost_v4)
        );
        assert_eq!(
            get_socket_address("http://[0:0:0:0:0:0:0:1]:8888/foo"),
            Some(localhost_v6)
        );
        assert_eq!(
            get_socket_address("http://[::1]:8888/foo"),
            Some(localhost_v6)
        );

        // Non-loopback addresses
        assert_eq!(get_socket_address("http://8.8.8.8:1234/foo"), Some(addr_v4));
        assert_eq!(
            get_socket_address("http://[2001:4860:4860::8888]:8888/foo"),
            Some(addr_v6)
        );
    }
}
