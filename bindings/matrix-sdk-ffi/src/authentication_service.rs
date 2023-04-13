use std::{
    collections::HashMap,
    fs,
    fs::File,
    io::{BufReader, BufWriter},
    path::PathBuf,
    sync::{Arc, RwLock},
};

use futures_util::future::join3;
use matrix_sdk::{
    oidc::{
        types::{
            client_credentials::ClientCredentials,
            iana::oauth::OAuthClientAuthenticationMethod,
            oidc::ApplicationType,
            registration::{ClientMetadata, Localized, VerifiedClientMetadata},
            requests::GrantType,
        },
        AuthorizationResponse, Oidc, OidcError,
    },
    ruma::{IdParseError, OwnedUserId},
};
use serde::{Deserialize, Serialize};
use url::Url;
use zeroize::Zeroize;

use super::{client::Client, client_builder::ClientBuilder, RUNTIME};
use crate::error::ClientError;

#[derive(uniffi::Object)]
pub struct AuthenticationService {
    base_path: String,
    passphrase: Option<String>,
    client: RwLock<Option<Arc<Client>>>,
    homeserver_details: RwLock<Option<Arc<HomeserverLoginDetails>>>,
    oidc_configuration: Option<OidcConfiguration>,
    custom_sliding_sync_proxy: RwLock<Option<String>>,
}

impl Drop for AuthenticationService {
    fn drop(&mut self) {
        self.passphrase.zeroize();
    }
}

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum AuthenticationError {
    #[error("A successful call to configure_homeserver must be made first.")]
    ClientMissing,
    #[error("{message}")]
    InvalidServerName { message: String },
    #[error("The homeserver doesn't provide a trusted sliding sync proxy in its well-known configuration.")]
    SlidingSyncNotAvailable,
    #[error("Login was successful but is missing a valid Session to configure the file store.")]
    SessionMissing,
    #[error("Failed to use the supplied base path.")]
    InvalidBasePath,
    #[error(
        "The homeserver doesn't provide an authentication issuer in its well-known configuration."
    )]
    OidcNotSupported,
    #[error("Unable to use OIDC as no client metadata has been supplied.")]
    OidcMetadataMissing,
    #[error("Unable to use OIDC as the supplied client metadata is invalid.")]
    OidcMetadataInvalid,
    #[error("The call to complete OIDC must be made after a call to login with OIDC.")]
    OidcNotStarted,
    #[error("The supplied callback URL used to complete OIDC is invalid.")]
    OidcCallbackUrlInvalid,
    #[error("The OIDC login was cancelled by the user.")]
    OidcCancelled,
    #[error("An error occurred with OIDC: {message}")]
    OidcError { message: String },
    #[error("An error occurred: {message}")]
    Generic { message: String },
}

impl From<anyhow::Error> for AuthenticationError {
    fn from(e: anyhow::Error) -> AuthenticationError {
        AuthenticationError::Generic { message: e.to_string() }
    }
}

impl From<IdParseError> for AuthenticationError {
    fn from(e: IdParseError) -> AuthenticationError {
        AuthenticationError::InvalidServerName { message: e.to_string() }
    }
}

impl From<OidcError> for AuthenticationError {
    fn from(e: OidcError) -> AuthenticationError {
        AuthenticationError::OidcError { message: e.to_string() }
    }
}

/// The configuration to use when authenticating with OIDC.
#[derive(uniffi::Record)]
pub struct OidcConfiguration {
    /// The name of the client that will be shown during OIDC authentication.
    pub client_name: String,
    /// The redirect URI that will be used when OIDC authentication is
    /// successful.
    pub redirect_uri: String,
    /// A URI that contains information about the client.
    pub client_uri: String,
    /// A URI that contains the client's terms of service.
    pub tos_uri: String,
    /// A URI that contains the client's privacy policy.
    pub policy_uri: String,

    /// Pre-configured registrations for use with issuers that don't support
    /// dynamic client registration.
    pub static_registrations: HashMap<String, String>,
}

/// The data needed to restore an OpenID Connect session.
#[derive(Debug, Serialize, Deserialize)]
struct OidcRegistrations {
    /// The URL of the OIDC Provider.
    file_path: PathBuf,
    /// Pre-configured registrations for use with issuers that don't support
    /// dynamic client registration.
    static_registrations: HashMap<String, String>,
}

impl OidcRegistrations {
    fn new(
        base_path: &str,
        static_registrations: HashMap<String, String>,
    ) -> Result<Self, AuthenticationError> {
        let oidc_directory = PathBuf::from(base_path).join("oidc");
        fs::create_dir_all(&oidc_directory).map_err(|_| AuthenticationError::InvalidBasePath)?;

        Ok(OidcRegistrations {
            file_path: oidc_directory.join("registrations.json"),
            static_registrations,
        })
    }

    fn dynamic_registrations(&self) -> HashMap<String, String> {
        let Some(file) = File::open(&self.file_path).ok() else {
            return HashMap::new();
        };
        let reader = BufReader::new(file);

        let Some(registrations): Option<HashMap<String, String>> = serde_json::from_reader(reader).ok() else {
            return HashMap::new();
        };

        registrations
    }

    fn client_id(&self, issuer: String) -> Option<String> {
        let mut registrations = self.dynamic_registrations();
        registrations.extend(self.static_registrations.clone());
        registrations.get(&issuer).cloned()
    }

    fn set_client_id(&self, client_id: String, issuer: String) -> Result<(), AuthenticationError> {
        let mut current = self.dynamic_registrations();
        current.insert(issuer, client_id);

        let writer = BufWriter::new(
            File::create(&self.file_path).map_err(|_| AuthenticationError::InvalidBasePath)?,
        );
        serde_json::to_writer(writer, &current).map_err(|_| AuthenticationError::InvalidBasePath)
    }
}

#[derive(uniffi::Object)]
pub struct OidcAuthenticationData {
    url: Url,
    state: String,
}

#[uniffi::export]
impl OidcAuthenticationData {
    pub fn login_url(&self) -> String {
        let mut prompt_url = self.url.clone();
        prompt_url.query_pairs_mut().append_pair("prompt", "consent");
        prompt_url.to_string()
    }
}

#[derive(uniffi::Object)]
pub struct HomeserverLoginDetails {
    url: String,
    supports_oidc_login: bool,
    supports_password_login: bool,
}

#[uniffi::export]
impl HomeserverLoginDetails {
    /// The URL of the currently configured homeserver.
    pub fn url(&self) -> String {
        self.url.clone()
    }

    /// Whether the current homeserver supports login using OIDC.
    pub fn supports_oidc_login(&self) -> bool {
        self.supports_oidc_login
    }

    /// Whether the current homeserver supports the password login flow.
    pub fn supports_password_login(&self) -> bool {
        self.supports_password_login
    }
}

#[uniffi::export]
impl AuthenticationService {
    /// Creates a new service to authenticate a user with.
    #[uniffi::constructor]
    pub fn new(
        base_path: String,
        passphrase: Option<String>,
        oidc_configuration: Option<OidcConfiguration>,
        custom_sliding_sync_proxy: Option<String>,
    ) -> Arc<Self> {
        Arc::new(AuthenticationService {
            base_path,
            passphrase,
            client: RwLock::new(None),
            homeserver_details: RwLock::new(None),
            oidc_configuration,
            custom_sliding_sync_proxy: RwLock::new(custom_sliding_sync_proxy),
        })
    }

    pub fn homeserver_details(&self) -> Option<Arc<HomeserverLoginDetails>> {
        self.homeserver_details.read().unwrap().clone()
    }

    /// Updates the service to authenticate with the homeserver for the
    /// specified address.
    pub fn configure_homeserver(
        &self,
        server_name_or_homeserver_url: String,
    ) -> Result<(), AuthenticationError> {
        let mut builder = ClientBuilder::new().base_path(self.base_path.clone());

        // Attempt discovery as a server name first.
        let result = matrix_sdk::sanitize_server_name(&server_name_or_homeserver_url);
        match result {
            Ok(server_name) => {
                let is_http_url = server_name_or_homeserver_url.starts_with("http://");
                builder = builder
                    .server_name(server_name.to_string())
                    .insecure_http_discovery(is_http_url);
            }
            Err(e) => {
                // When the input isn't a valid server name check it is a URL.
                // If this is the case, build the client with a homeserver URL.
                if let Ok(_url) = Url::parse(&server_name_or_homeserver_url) {
                    builder = builder.homeserver_url(server_name_or_homeserver_url.clone());
                } else {
                    return Err(e.into());
                }
            }
        }

        let client = builder.build_inner().or_else(|e| {
            if !server_name_or_homeserver_url.starts_with("http://")
                && !server_name_or_homeserver_url.starts_with("https://")
            {
                return Err(e);
            }
            // When discovery fails, fallback to the homeserver URL if supplied.
            let mut builder = ClientBuilder::new().base_path(self.base_path.clone());
            builder = builder.homeserver_url(server_name_or_homeserver_url);
            builder.build_inner()
        })?;

        let details = RUNTIME.block_on(self.details_from_client(&client))?;

        // Now we've verified that it's a valid homeserver, make sure
        // there's a sliding sync proxy available one way or another.
        if self.custom_sliding_sync_proxy.read().unwrap().is_none()
            && client.discovered_sliding_sync_proxy().is_none()
        {
            return Err(AuthenticationError::SlidingSyncNotAvailable);
        }

        *self.client.write().unwrap() = Some(client);
        *self.homeserver_details.write().unwrap() = Some(Arc::new(details));

        Ok(())
    }

    pub fn url_for_oidc_login(&self) -> Result<Arc<OidcAuthenticationData>, AuthenticationError> {
        let Some(client) = self.client.read().unwrap().clone() else {
            return Err(AuthenticationError::ClientMissing);
        };

        if RUNTIME.block_on(client.authentication_issuer()).is_none() {
            return Err(AuthenticationError::OidcNotSupported);
        }

        let Some(oidc_configuration) = &self.oidc_configuration else {
            return Err(AuthenticationError::OidcMetadataMissing);
        };

        let redirect_url = Url::parse(&oidc_configuration.redirect_uri)
            .map_err(|_e| AuthenticationError::OidcMetadataInvalid)?;

        let oidc = client.inner.oidc();

        RUNTIME.block_on(async {
            self.configure_oidc(&oidc, &oidc_configuration).await?;

            let data = oidc.login().url_for_login_with_authorization_code(&redirect_url).await?;

            Ok(Arc::new(OidcAuthenticationData { url: data.url, state: data.state }))
        })
    }

    pub fn login_with_oidc_callback(
        &self,
        authentication_data: Arc<OidcAuthenticationData>,
        callback_url: String,
    ) -> Result<Arc<Client>, AuthenticationError> {
        let Some(client) = self.client.read().unwrap().clone() else {
            return Err(AuthenticationError::ClientMissing);
        };

        let oidc = client.inner.oidc();

        let url =
            Url::parse(&callback_url).map_err(|_| AuthenticationError::OidcCallbackUrlInvalid)?;

        let Ok(response) = AuthorizationResponse::parse_uri(&url) else {
            let callback_url_query: HashMap<_, _> = url.query_pairs().into_owned().collect();
            let Some(error) = callback_url_query.get("error") else {
                return Err(AuthenticationError::OidcCallbackUrlInvalid);
            };

            // Use AuthorizationError once error_description it an optional.
            if error == "access_denied" {
                return Err(AuthenticationError::OidcCancelled);
            }
            return Err(AuthenticationError::OidcError { message: error.to_owned() });
        };

        if response.state != authentication_data.state {
            return Err(AuthenticationError::OidcCallbackUrlInvalid);
        };

        RUNTIME.block_on(async move {
            oidc.login()
                .finish_login_with_authorization_code(AuthorizationResponse {
                    code: response.code,
                    state: response.state,
                })
                .await
        })?;

        let user_id = client.inner.user_id().unwrap().to_owned();
        self.finalize_client(client, user_id)
    }

    /// Performs a password login using the current homeserver.
    pub fn login(
        &self,
        username: String,
        password: String,
        initial_device_name: Option<String>,
        device_id: Option<String>,
    ) -> Result<Arc<Client>, AuthenticationError> {
        let Some(client) = self.client.read().unwrap().clone() else {
            return Err(AuthenticationError::ClientMissing);
        };

        // Login and ask the server for the full user ID as this could be different from
        // the username that was entered.
        client.login(username, password, initial_device_name, device_id).map_err(|e| match e {
            ClientError::Generic { msg } => AuthenticationError::Generic { message: msg },
        })?;
        let whoami = client.whoami()?;

        self.finalize_client(client, whoami.user_id)
    }
}

impl AuthenticationService {
    /// Creates a new client to setup the store path now the user ID is known.
    fn finalize_client(
        &self,
        client: Arc<Client>,
        user_id: OwnedUserId,
    ) -> Result<Arc<Client>, AuthenticationError> {
        let homeserver_url = client.homeserver();
        let session = client.inner.session().ok_or(AuthenticationError::SessionMissing)?;

        let sliding_sync_proxy: Option<String>;
        if let Some(custom_proxy) = self.custom_sliding_sync_proxy.read().unwrap().clone() {
            sliding_sync_proxy = Some(custom_proxy);
        } else if let Some(discovered_proxy) = client.discovered_sliding_sync_proxy() {
            sliding_sync_proxy = Some(discovered_proxy);
        } else {
            sliding_sync_proxy = None;
        }

        let oidc_data = if session.authenticates_with_oidc {
            Some(RUNTIME.block_on(client.oidc_data())?)
        } else {
            None
        };

        let client = ClientBuilder::new()
            .base_path(self.base_path.clone())
            .passphrase(self.passphrase.clone())
            .homeserver_url(homeserver_url)
            .sliding_sync_proxy(sliding_sync_proxy)
            .username(user_id.to_string())
            .build_inner()?;

        // Restore the client using the session from the login request.
        client.restore_session_inner(session)?;

        if let Some(oidc_data) = oidc_data {
            client.restore_oidc(oidc_data);
        }

        Ok(client)
    }

    /// Get the homeserver login details from a client.
    async fn details_from_client(
        &self,
        client: &Arc<Client>,
    ) -> Result<HomeserverLoginDetails, AuthenticationError> {
        let login_details = join3(
            client.async_homeserver(),
            client.authentication_issuer(),
            client.supports_password_login(),
        )
        .await;

        let url = login_details.0;
        let supports_oidc_login = login_details.1.is_some();
        let supports_password_login = login_details.2.ok().unwrap_or(false);

        Ok(HomeserverLoginDetails { url, supports_oidc_login, supports_password_login })
    }

    async fn configure_oidc(
        &self,
        oidc: &Oidc,
        configuration: &OidcConfiguration,
    ) -> Result<(), AuthenticationError> {
        if oidc.client_credentials().is_some() {
            tracing::info!("OIDC is already configured.");
            return Ok(());
        };

        let oidc_metadata = self.oidc_metadata(configuration)?;

        if self.load_client_registration(&oidc, oidc_metadata.clone()).await {
            tracing::info!("OIDC configuration loaded from disk.");
            return Ok(());
        }

        tracing::info!("Registering this client for OIDC.");
        let registration_response = oidc.register_client(oidc_metadata.clone(), None).await?;

        let client_credentials =
            ClientCredentials::None { client_id: registration_response.client_id.clone() };
        oidc.set_registered_client_data(oidc_metadata, client_credentials, None).await;

        tracing::info!("Persisting OIDC registration data.");
        self.store_client_registration(oidc).await?;

        Ok(())
    }

    async fn store_client_registration(&self, oidc: &Oidc) -> Result<(), AuthenticationError> {
        let issuer = oidc.issuer().await.ok_or(AuthenticationError::OidcNotSupported)?;
        let client_id = oidc
            .client_credentials()
            .ok_or(AuthenticationError::OidcError {
                message: String::from("Missing client registration."),
            })?
            .client_id()
            .to_owned();

        let registrations = OidcRegistrations::new(
            &self.base_path,
            self.oidc_configuration
                .as_ref()
                .map(|c| c.static_registrations.clone())
                .unwrap_or(HashMap::new()),
        )?;
        registrations.set_client_id(client_id, issuer)?;

        Ok(())
    }

    async fn load_client_registration(
        &self,
        oidc: &Oidc,
        oidc_metadata: VerifiedClientMetadata,
    ) -> bool {
        let Some(issuer) = oidc.issuer().await else {
            return false;
        };
        let Some(registrations) = OidcRegistrations::new(
            &self.base_path,
            self.oidc_configuration
                .as_ref()
                .map(|c| c.static_registrations.clone())
                .unwrap_or(HashMap::new()),
        ).ok() else {
            return false;
        };
        let Some(client_id) = registrations.client_id(issuer.clone()) else {
            return false;
        };

        oidc.set_registered_client_data(
            oidc_metadata,
            ClientCredentials::None { client_id },
            Some(issuer),
        )
        .await;

        true
    }

    /// Creates OIDC client metadata for the current configuration.
    fn oidc_metadata(
        &self,
        configuration: &OidcConfiguration,
    ) -> Result<VerifiedClientMetadata, AuthenticationError> {
        let redirect_uri = Url::parse(&configuration.redirect_uri)
            .map_err(|_| AuthenticationError::OidcCallbackUrlInvalid)?;
        let client_name = Some(Localized::new(configuration.client_name.to_owned(), []));
        let client_uri = Url::parse(&configuration.client_uri).ok().map(|u| Localized::new(u, []));
        let policy_uri = Url::parse(&configuration.policy_uri).ok().map(|u| Localized::new(u, []));
        let tos_uri = Url::parse(&configuration.tos_uri).ok().map(|u| Localized::new(u, []));

        ClientMetadata {
            application_type: Some(ApplicationType::Native),
            redirect_uris: Some(vec![redirect_uri]),
            grant_types: Some(vec![GrantType::RefreshToken, GrantType::AuthorizationCode]),
            // A native client shouldn't use authentication as the credentials could be intercepted.
            token_endpoint_auth_method: Some(OAuthClientAuthenticationMethod::None),
            // The server should display the following fields when getting the user's consent.
            client_name,
            contacts: None,
            client_uri,
            policy_uri,
            tos_uri,
            ..Default::default()
        }
        .validate()
        .map_err(|_| AuthenticationError::OidcMetadataInvalid)
    }
}
