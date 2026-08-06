#![warn(missing_docs)]
//! Provides a Spotify access token using the OAuth authorization code flow
//! with PKCE.
//!
//! Assuming sufficient scopes, the returned access token may be used with Spotify's
//! Web API, and/or to establish a new Session with [`librespot_core`].
//!
//! The authorization code flow is an interactive process which requires a web browser
//! to complete. The resulting code must then be provided back from the browser to this
//! library for exchange into an access token. Providing the code can be automatic via
//! a spawned http server (mimicking Spotify's client), or manually via stdin. The latter
//! is appropriate for headless systems.

use std::{
    io::{self, BufRead, BufReader, Write},
    net::{SocketAddr, TcpListener},
    sync::mpsc,
    time::{Duration, Instant},
};

use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, CsrfToken, EmptyExtraTokenFields, EndpointNotSet,
    EndpointSet, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RefreshToken, Scope,
    StandardTokenResponse, TokenResponse, TokenUrl, basic::BasicClient, basic::BasicTokenType,
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

/// How long to wait for a request line before giving up on a connection and
/// listening for the next one, so a browser that opens a socket without ever
/// writing to it cannot park the login forever.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// How many blank lines to read past on a single connection, and how many
/// unusable connections to tolerate overall. Both exist only so a misbehaving
/// client cannot keep the server alive indefinitely.
const MAX_BLANK_LINES: usize = 8;
const MAX_SKIPPED_REQUESTS: usize = 64;

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
fn read_request_line(reader: &mut impl BufRead) -> Option<String> {
    for _ in 0..MAX_BLANK_LINES {
        let mut line = String::new();
        match reader.read_line(&mut line) {
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
/// Split out from `get_authcode_listener` so tests can supply a listener bound to
/// port 0 rather than racing for a fixed port.
fn accept_authcode(
    listener: &TcpListener,
    message: String,
) -> Result<AuthorizationCode, OAuthError> {
    let mut skipped = 0usize;

    for incoming in listener.incoming() {
        if skipped >= MAX_SKIPPED_REQUESTS {
            warn!("OAuth callback: too many unusable requests, giving up");
            return Err(OAuthError::AuthCodeListenerTerminated);
        }

        let mut stream = match incoming {
            Ok(stream) => stream,
            Err(e) => {
                debug!("OAuth callback accept error, still listening: {e}");
                skipped += 1;
                continue;
            }
        };
        // Bounded so a connection that never sends a request line cannot block
        // the login; the real redirect waits in the accept backlog meanwhile.
        let _ = stream.set_read_timeout(Some(REQUEST_READ_TIMEOUT));

        let mut reader = BufReader::new(&stream);
        let Some(request_line) = read_request_line(&mut reader) else {
            debug!("OAuth callback: no request line, still listening");
            skipped += 1;
            continue;
        };

        let Some(redirect_url) = request_line.split_whitespace().nth(1) else {
            debug!("OAuth callback: unparseable request line, still listening");
            skipped += 1;
            continue;
        };

        match get_code(&("http://localhost".to_string() + redirect_url)) {
            Ok(code) => {
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{}",
                    message.len(),
                    message
                );
                stream
                    .write_all(response.as_bytes())
                    .map_err(|_| OAuthError::AuthCodeListenerWrite)?;

                return Ok(code);
            }
            // Browser noise (`/favicon.ico`, `/`, a pre-flight). Answer it so the
            // browser is not left hanging, then keep waiting for the redirect.
            Err(e) => {
                debug!("OAuth callback: request carried no code ({e}), still listening");
                let _ = stream.write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\n\r\n");
                skipped += 1;
            }
        }
    }

    Err(OAuthError::AuthCodeListenerTerminated)
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
        trace!("Obtained new access token: {resp:?}");

        let token_scopes: Vec<String> = match resp.scopes() {
            Some(s) => s.iter().map(|s| s.to_string()).collect(),
            _ => self.scopes.clone(),
        };
        let refresh_token = match resp.refresh_token() {
            Some(t) => t.secret().to_string(),
            _ => "".to_string(), // Spotify always provides a refresh token.
        };
        Ok(OAuthToken {
            access_token: resp.access_token().secret().to_string(),
            refresh_token,
            expires_at: Instant::now()
                + resp
                    .expires_in()
                    .unwrap_or_else(|| Duration::from_secs(3600)),
            token_type: format!("{:?}", resp.token_type()),
            scopes: token_scopes,
        })
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
        let auth_url = AuthUrl::new("https://accounts.spotify.com/authorize".to_string())
            .map_err(|_| OAuthError::InvalidSpotifyUri)?;
        let token_url = TokenUrl::new("https://accounts.spotify.com/api/token".to_string())
            .map_err(|_| OAuthError::InvalidSpotifyUri)?;
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
    let auth_url = AuthUrl::new("https://accounts.spotify.com/authorize".to_string())
        .map_err(|_| OAuthError::InvalidSpotifyUri)?;
    let token_url = TokenUrl::new("https://accounts.spotify.com/api/token".to_string())
        .map_err(|_| OAuthError::InvalidSpotifyUri)?;
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
        _ => scopes.into_iter().map(|s| s.to_string()).collect(),
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

#[cfg(test)]
mod test {
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};

    use super::*;

    const CODE_REQUEST: &str = "GET /login?code=testcode123 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";

    /// Drive `accept_authcode` against a listener on port 0 while `client` talks
    /// to it, and return whatever the server resolved.
    fn run_listener(
        client: impl FnOnce(SocketAddr) + Send + 'static,
    ) -> Result<AuthorizationCode, OAuthError> {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        let handle = std::thread::spawn(move || client(addr));
        let result = accept_authcode(&listener, "done".to_string());
        handle.join().expect("client thread panicked");
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

    #[test]
    fn gives_up_after_too_many_unusable_requests() {
        let result = run_listener(|addr| {
            for _ in 0..(MAX_SKIPPED_REQUESTS + 1) {
                drop(TcpStream::connect(addr).expect("connect"));
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
