package cj.geochat.ability.oauth.server.convert;

import cj.geochat.ability.oauth.server.OAuth2AuthenticationException;
import cj.geochat.ability.oauth.server.OAuth2AuthorizationCodeRequestAuthenticationException;
import cj.geochat.ability.oauth.server.OAuth2Error;
import cj.geochat.ability.oauth.server.OAuth2ErrorCodes;
import cj.geochat.ability.oauth.server.annotation.CjAuthConverter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class DelegatingGrantTypeConverter implements IAuthenticationConverter {
    private final Map<String, IAuthenticationConverter> converters;
    private final String defaultConverter;

    /**
     * Constructs a {@code DelegatingAuthenticationConverter} using the provided parameters.
     *
     * @param defaultConverter
     * @param converters       a {@code List} of {@link IAuthenticationConverter}(s)
     */
    public DelegatingGrantTypeConverter(String defaultConverter, List<IAuthenticationConverter> converters) {
        Assert.notEmpty(converters, "converters cannot be empty");
        this.defaultConverter=defaultConverter;
        this.converters = new HashMap<>();
        for (IAuthenticationConverter converter : converters) {
            CjAuthConverter authType = converter.getClass().getAnnotation(CjAuthConverter.class);
            if (authType == null) {
                continue;
            }
            this.converters.put(authType.value(), converter);
        }
    }

    @Override
    public AbstractAuthenticationToken convert(HttpServletRequest request) {
        Assert.notNull(request, "request cannot be null");
        String[] auth_type_arr = request.getParameterMap().get("grant_type");
        String auth_type = defaultConverter;
        if (auth_type_arr != null && auth_type_arr.length > 0) {
            auth_type = auth_type_arr[0];
        }
        if (!converters.containsKey(auth_type)) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Authentication type not supported:: " + auth_type, null);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(error,null);
        }
        var convert = converters.get(auth_type);
        AbstractAuthenticationToken authRequest = convert.convert(request);
        return authRequest;
    }
}
