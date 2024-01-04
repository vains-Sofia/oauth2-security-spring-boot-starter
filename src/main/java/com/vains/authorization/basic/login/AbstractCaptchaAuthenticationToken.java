package com.vains.authorization.basic.login;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * 验证码登录token
 *
 * @author vains 2023/12/15
 */
@Getter
@Setter
public abstract class AbstractCaptchaAuthenticationToken extends AbstractAuthenticationToken {

    /**
     * 手机号/邮箱/../用户信息
     */
    private Object principal;

    /**
     * Creates a token with the supplied array of authorities.
     *
     * @param authorities the collection of <tt>GrantedAuthority</tt>s for the principal
     *                    represented by this authentication object.
     * @param principal   account
     */
    public AbstractCaptchaAuthenticationToken(Object principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        setAuthenticated(false);
    }

    /**
     * 默认构造器，设置当前认证信息
     *
     * @param principal account
     */
    public AbstractCaptchaAuthenticationToken(Object principal) {
        super(null);
        this.principal = principal;
        setAuthenticated(false);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

}