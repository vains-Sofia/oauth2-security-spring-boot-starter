package com.vains.authorization.login.email;

import com.vains.authorization.basic.login.AbstractCaptchaAuthenticationToken;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * 邮箱认证登录token
 *
 * @author vains 2023/12/15
 */
@Getter
public class EmailLoginAuthenticationToken extends AbstractCaptchaAuthenticationToken {

    private EmailLoginAuthenticationToken(Object principal, Collection<? extends GrantedAuthority> authorities) {
        super(principal, authorities);
        setAuthenticated(Boolean.TRUE);
    }

    public EmailLoginAuthenticationToken(Object principal) {
        super(principal);
    }

    /**
     * 创建一个未认证的实例
     *
     * @param principal 邮箱地址
     * @return SmsLoginAuthenticationToken
     */
    public static EmailLoginAuthenticationToken unauthenticated(Object principal) {
        return new EmailLoginAuthenticationToken(principal);
    }

    /**
     * 创建一个认证过的实例
     *
     * @param principal 邮箱地址
     * @return SmsLoginAuthenticationToken
     */
    public static EmailLoginAuthenticationToken authenticated(Object principal, Collection<? extends GrantedAuthority> authorities) {
        return new EmailLoginAuthenticationToken(principal, authorities);
    }

}