package cj.geochat.ability.oauth.server.login.method.guest;

import cj.geochat.ability.oauth.server.entrypoint.verifycode.IVerifyCodeService;
import cj.geochat.ability.oauth.server.entrypoint.verifycode.VerifyCodeInfo;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

public class GuestCodeAuthenticationProvider implements AuthenticationProvider {
    private UserDetailsService userDetailsService;
    private IVerifyCodeService verifyCodeService;

    public GuestCodeAuthenticationProvider(IVerifyCodeService verifyCodeService, UserDetailsService userDetailsService) {
        this.verifyCodeService = verifyCodeService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        GuestCodeAuthenticationToken adminLoginToken = (GuestCodeAuthenticationToken) authentication;
//        System.out.println("===进入Admin密码登录验证环节====="+ JSON.toJSONString(adminLoginToken));
        UserDetails userDetails = userDetailsService.loadUserByUsername(adminLoginToken.getName());
        //matches方法，前面为明文，后续为加密后密文
        //匹配密码。进行密码校验
        if (verifyCodeService == null) {
            throw new BadCredentialsException("Missing verification code service. ");
        }
        VerifyCodeInfo verifyCodeInfo = verifyCodeService.read(adminLoginToken.getName());
        if (verifyCodeInfo == null) {
            throw new BadCredentialsException("Missing verification code. ");
        }
        if (authentication.getCredentials().toString().equals(verifyCodeInfo.getCode())) {
            return new GuestCodeAuthenticationToken(userDetails, verifyCodeInfo.getCode(), userDetails.getAuthorities());
        }
        throw new BadCredentialsException("Incorrect username and password. ");
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return GuestCodeAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
