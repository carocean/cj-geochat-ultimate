package cj.geochat.ability.oauth.server.convert;

import cj.geochat.ability.oauth.server.annotation.CjAuthConverter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.util.Assert;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class DelegatingAuthTypeConverter implements IAuthenticationConverter {
    private final Map<String, IAuthenticationConverter> converters;
    private final String defaultConverter;

    /**
     * Constructs a {@code DelegatingAuthenticationConverter} using the provided parameters.
     *
     * @param defaultConverter
     * @param converters       a {@code List} of {@link IAuthenticationConverter}(s)
     */
    public DelegatingAuthTypeConverter(String defaultConverter, List<IAuthenticationConverter> converters) {
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
        String[] auth_type_arr = request.getParameterMap().get("auth_type");
        String auth_type = defaultConverter;
        if (auth_type_arr != null && auth_type_arr.length > 0) {
            auth_type = auth_type_arr[0];
        }
        if (!converters.containsKey(auth_type)) {
            throw new AuthenticationServiceException("Authentication type not supported: " + auth_type);
        }
        var convert = converters.get(auth_type);
        AbstractAuthenticationToken authRequest = convert.convert(request);
        return authRequest;
    }
}
