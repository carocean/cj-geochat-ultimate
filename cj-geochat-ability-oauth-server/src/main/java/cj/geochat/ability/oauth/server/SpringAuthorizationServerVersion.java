package cj.geochat.ability.oauth.server;

/**
 * Internal class used for serialization across Spring Authorization Server classes.
 *
 * @author Anoop Garlapati
 * @since 0.0.1
 */
public final class SpringAuthorizationServerVersion {
	private static final int MAJOR = 1;
	private static final int MINOR = 1;
	private static final int PATCH = 0;

	/**
	 * Global Serialization value for Spring Authorization Server classes.
	 */
	public static final long SERIAL_VERSION_UID = getVersion().hashCode();

	public static String getVersion() {
		return MAJOR + "." + MINOR + "." + PATCH;
	}
}
