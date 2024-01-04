package com.vains.authorization.login.email;

import com.vains.authorization.basic.login.AbstractCaptchaLoginAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * 短信认证登录token
 *
 * @author vains 2023/12/15
 */
public class EmailLoginAuthenticationProvider extends AbstractCaptchaLoginAuthenticationProvider {

    public EmailLoginAuthenticationProvider(UserDetailsService userDetailsService) {
        super(userDetailsService);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UserDetails userDetails = super.loadUserDetails(authentication);
        // 重新生成，将认证信息改为用户信息
        return EmailLoginAuthenticationToken.authenticated(userDetails, userDetails.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return EmailLoginAuthenticationToken.class.isAssignableFrom(authentication);
    }

}