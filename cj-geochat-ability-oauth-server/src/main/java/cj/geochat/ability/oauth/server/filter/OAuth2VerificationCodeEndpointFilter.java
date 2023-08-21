package cj.geochat.ability.oauth.server.filter;

import cj.geochat.ability.api.R;
import cj.geochat.ability.api.ResultCode;
import cj.geochat.ability.oauth.server.*;
import cj.geochat.ability.oauth.server.entrypoint.verifycode.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class OAuth2VerificationCodeEndpointFilter extends OncePerRequestFilter {
    private final RequestMatcher checkTokenEndpointMatcher;
    private static final String DEFAULT_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    private IVerifyCodeProvider verifyCodeProvider;
    private IVerifyCodeRequestResolver verifyCodeRequestResolver;
    private IVerifyCodeService verifyCodeService;
    private VerifyCodeSuccessHandler verifyCodeSuccessHandler = this::sendVerifyCodeResponse;
    private VerifyCodeFailureHandler verifyCodeFailureHandler = this::sendErrorResponse;

    public OAuth2VerificationCodeEndpointFilter(String tokenEndpointUri) {
        Assert.hasText(tokenEndpointUri, "tokenEndpointUri cannot be empty");
        this.checkTokenEndpointMatcher = new AntPathRequestMatcher(tokenEndpointUri, HttpMethod.POST.name());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (!this.checkTokenEndpointMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }
        try {
            VerifyCodeRequest verifyCodeRequest = verifyCodeRequestResolver.resolve(request);
            if (verifyCodeRequest == null || !StringUtils.hasLength(verifyCodeRequest.getVerifyType())) {
                throwError(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.GRANT_TYPE);
            }
            String verifyCode = verifyCodeProvider.generate(verifyCodeRequest);
            if (!StringUtils.hasLength(verifyCode)) {
                throwError(OAuth2ErrorCodes.INVALID_TOKEN, OAuth2ParameterNames.CODE);
            }
            VerifyCodeInfo verifyCodeInfo = new VerifyCodeInfo(verifyCodeRequest, verifyCode);
            verifyCodeService.save(verifyCodeInfo);
            this.verifyCodeSuccessHandler.onVerifyCodeSuccess(request, response, verifyCodeInfo);
        } catch (OAuth2AuthenticationException ex) {
            if (this.logger.isTraceEnabled()) {
                this.logger.trace(LogMessage.format("Token request failed: %s", ex.getError()), ex);
            }
            this.verifyCodeFailureHandler.onVerifyCodeFailure(request, response, ex);
        }
    }

    private static void throwError(String errorCode, String parameterName) {
        OAuth2Error error = new OAuth2Error(errorCode, "OAuth 2.0 Parameter: " + parameterName, DEFAULT_ERROR_URI);
        throw new OAuth2AuthenticationException(error);
    }

    private void sendVerifyCodeResponse(HttpServletRequest request, HttpServletResponse response,
                                        VerifyCodeInfo verifyCodeInfo) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        ResultCode rc = ResultCode.SUCCESS_TOKEN;
        Map<String, Object> accessTokenObject = new HashMap<>();
        accessTokenObject.put("principal",verifyCodeInfo.getPrincipal());
        accessTokenObject.put("verify_type", verifyCodeInfo.getVerifyType());
        if ("guest_code".equals(verifyCodeInfo.getVerifyType())) {//其它类型的验证码不能反给客户端
            accessTokenObject.put("verify_code", verifyCodeInfo.getCode());
        }
        Object obj = R.of(rc, accessTokenObject);
        response.getOutputStream().write(new ObjectMapper().writeValueAsBytes(obj));

    }

    private void sendErrorResponse(HttpServletRequest request, HttpServletResponse response,
                                   AuthenticationException exception) throws IOException {
        response.setContentType(MediaType.APPLICATION_JSON_UTF8_VALUE);
        ResultCode rc = ResultCodeTranslator.translateException(exception);
        OAuth2Error error = ((OAuth2AuthenticationException) exception).getError();
        Map<String, Object> map = new HashMap<>();
        map.put("errorCode", error.getErrorCode());
        map.put("description", error.getDescription());
        Object obj = R.of(rc, map);
        response.getOutputStream().write(new ObjectMapper().writeValueAsBytes(obj));
    }

    public void setVerifyCodeProvider(IVerifyCodeProvider verifyCodeGenerator) {
        this.verifyCodeProvider = verifyCodeGenerator;
    }

    public void setVerifyCodeRequestResolver(IVerifyCodeRequestResolver verifyCodeRequestResolver) {
        this.verifyCodeRequestResolver = verifyCodeRequestResolver;
    }

    public void setVerifyCodeService(IVerifyCodeService verifyCodeService) {
        this.verifyCodeService = verifyCodeService;
    }

    public void setVerifyCodeSuccessHandler(VerifyCodeSuccessHandler verifyCodeSuccessHandler) {
        this.verifyCodeSuccessHandler = verifyCodeSuccessHandler;
    }

    public void setVerifyCodeFailureHandler(VerifyCodeFailureHandler verifyCodeFailureHandler) {
        this.verifyCodeFailureHandler = verifyCodeFailureHandler;
    }
}
