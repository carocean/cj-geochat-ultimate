package cj.geochat.ability.oauth.server.settings;

/**
 * The names for all the configuration settings.
 *
 * @author Joe Grandja
 * @since 0.2.0
 */
public final class ConfigurationSettingNames {
	private static final String SETTINGS_NAMESPACE = "settings.";

	private ConfigurationSettingNames() {
	}

	/**
	 * The names for client configuration settings.
	 */
	public static final class Client {
		private static final String CLIENT_SETTINGS_NAMESPACE = SETTINGS_NAMESPACE.concat("client.");

		/**
		 * Set to {@code true} if the client is required to provide a proof key challenge and verifier
		 * when performing the Authorization Code Grant flow.
		 */
		public static final String REQUIRE_PROOF_KEY = CLIENT_SETTINGS_NAMESPACE.concat("require-proof-key");

		/**
		 * Set to {@code true} if authorization consent is required when the client requests access.
		 * This applies to all interactive flows (e.g. {@code authorization_code} and {@code device_code}).
		 */
		public static final String REQUIRE_AUTHORIZATION_CONSENT = CLIENT_SETTINGS_NAMESPACE.concat("require-authorization-consent");

		/**
		 * Set the {@code URL} for the Client's JSON Web Key Set.
		 * @since 0.2.2
		 */
		public static final String JWK_SET_URL = CLIENT_SETTINGS_NAMESPACE.concat("jwk-set-url");


		public static final String TOKEN_ENDPOINT_AUTHENTICATION_SIGNING_ALGORITHM = CLIENT_SETTINGS_NAMESPACE.concat("token-endpoint-authentication-signing-algorithm");

		private Client() {
		}

	}

	/**
	 * The names for authorization server configuration settings.
	 */
	public static final class AuthorizationServer {
		private static final String AUTHORIZATION_SERVER_SETTINGS_NAMESPACE = SETTINGS_NAMESPACE.concat("authorization-server.");

		/**
		 * Set the URL the Authorization Server uses as its Issuer Identifier.
		 */
		public static final String ISSUER = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE.concat("issuer");

		/**
		 * Set the OAuth 2.0 Authorization endpoint.
		 */
		public static final String AUTHORIZATION_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE.concat("authorization-endpoint");

		/**
		 * Set the OAuth 2.0 Token endpoint.
		 */
		public static final String TOKEN_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE.concat("token-endpoint");

		/**
		 * Set the OAuth 2.0 Token Revocation endpoint.
		 */
		public static final String TOKEN_REVOCATION_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE.concat("token-revocation-endpoint");
		public static final String CHECK_TOKEN_ENDPOINT = AUTHORIZATION_SERVER_SETTINGS_NAMESPACE.concat("check-token-endpoint");


		private AuthorizationServer() {
		}

	}

	/**
	 * The names for token configuration settings.
	 */
	public static final class Token {
		private static final String TOKEN_SETTINGS_NAMESPACE = SETTINGS_NAMESPACE.concat("token.");

		/**
		 * Set the time-to-live for an authorization code.
		 * @since 0.4.0
		 */
		public static final String AUTHORIZATION_CODE_TIME_TO_LIVE = TOKEN_SETTINGS_NAMESPACE.concat("authorization-code-time-to-live");

		/**
		 * Set the time-to-live for an access token.
		 */
		public static final String ACCESS_TOKEN_TIME_TO_LIVE = TOKEN_SETTINGS_NAMESPACE.concat("access-token-time-to-live");

		public static final String ACCESS_TOKEN_FORMAT = TOKEN_SETTINGS_NAMESPACE.concat("access-token-format");

		/**
		 * Set the time-to-live for a refresh token.
		 */
		public static final String REFRESH_TOKEN_TIME_TO_LIVE = TOKEN_SETTINGS_NAMESPACE.concat("refresh-token-time-to-live");

		private Token() {
		}

	}

}