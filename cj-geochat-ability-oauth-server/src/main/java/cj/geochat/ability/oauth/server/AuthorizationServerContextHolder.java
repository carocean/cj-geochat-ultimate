package cj.geochat.ability.oauth.server;

/**
 * A holder of the {@link AuthorizationServerContext} that associates it with the current thread using a {@code ThreadLocal}.
 *
 * @author Joe Grandja
 * @since 0.2.2
 * @see AuthorizationServerContext
 */
public final class AuthorizationServerContextHolder {
	private static final ThreadLocal<AuthorizationServerContext> holder = new ThreadLocal<>();

	private AuthorizationServerContextHolder() {
	}

	/**
	 * Returns the {@link AuthorizationServerContext} bound to the current thread.
	 *
	 * @return the {@link AuthorizationServerContext}
	 */
	public static AuthorizationServerContext getContext() {
		return holder.get();
	}

	/**
	 * Bind the given {@link AuthorizationServerContext} to the current thread.
	 *
	 * @param authorizationServerContext the {@link AuthorizationServerContext}
	 */
	public static void setContext(AuthorizationServerContext authorizationServerContext) {
		if (authorizationServerContext == null) {
			resetContext();
		} else {
			holder.set(authorizationServerContext);
		}
	}

	/**
	 * Reset the {@link AuthorizationServerContext} bound to the current thread.
	 */
	public static void resetContext() {
		holder.remove();
	}

}
