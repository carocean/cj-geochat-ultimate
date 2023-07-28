package cj.geochat.ability.oauth.server.convert;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AbstractAuthenticationToken;

public interface IAuthenticationConverter {
    AbstractAuthenticationToken convert(HttpServletRequest request);
}
