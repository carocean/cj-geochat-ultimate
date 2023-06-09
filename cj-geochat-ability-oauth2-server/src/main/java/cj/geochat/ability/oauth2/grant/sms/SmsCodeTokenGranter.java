package cj.geochat.ability.oauth2.grant.sms;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import java.util.LinkedHashMap;
import java.util.Map;

public class SmsCodeTokenGranter extends AbstractTokenGranter {
   // 仅仅复制了 ResourceOwnerPasswordTokenGranter，只是改变了 GRANT_TYPE 的值，来验证自定义授权模式的可行性
   public static final String GRANT_TYPE = "sms_code";

   private final AuthenticationManager authenticationManager;

   public SmsCodeTokenGranter(
       AuthenticationManager authenticationManager,
       AuthorizationServerTokenServices tokenServices,
       ClientDetailsService clientDetailsService,
       OAuth2RequestFactory requestFactory) {
       this(authenticationManager, tokenServices, clientDetailsService, requestFactory, GRANT_TYPE);

   }

   protected SmsCodeTokenGranter(
       AuthenticationManager authenticationManager,
       AuthorizationServerTokenServices tokenServices,
       ClientDetailsService clientDetailsService,
       OAuth2RequestFactory requestFactory,
       String grantType) {
       super(tokenServices, clientDetailsService, requestFactory, grantType);
       this.authenticationManager = authenticationManager;
   }

   @Override

   protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
       Map<String, String> parameters = new LinkedHashMap<String, String>(tokenRequest.getRequestParameters());
       // 获取参数
       String phone_num = parameters.get("phone_num");
       String smsCode = parameters.get("sms_code");

       Authentication userAuth = new SmsCodeAuthenticationToken(phone_num, smsCode);
       ((AbstractAuthenticationToken) userAuth).setDetails(parameters);
       try {
           userAuth = authenticationManager.authenticate(userAuth);
       } catch (AccountStatusException ase) {
           //covers expired, locked, disabled cases (mentioned in section 5.2, draft 31)
           throw new InvalidGrantException(ase.getMessage());
       } catch (BadCredentialsException e) {
           // If the username/password are wrong the spec says we should send 400/invalid grant
           throw new InvalidGrantException(e.getMessage());
       }
       if (userAuth == null || !userAuth.isAuthenticated()) {
           throw new InvalidGrantException("Could not authenticate user: " + phone_num);
       }

       OAuth2Request storedOAuth2Request = getRequestFactory().createOAuth2Request(client, tokenRequest);
       return new OAuth2Authentication(storedOAuth2Request, userAuth);
   }
}

