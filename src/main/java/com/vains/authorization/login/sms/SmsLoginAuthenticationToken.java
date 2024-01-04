package com.vains.authorization.login.sms;

import com.vains.authorization.basic.login.AbstractCaptchaAuthenticationToken;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * 短信认证登录token
 *
 * @author vains 2023/12/15
 */
@Getter
public class SmsLoginAuthenticationToken extends AbstractCaptchaAuthenticationToken {

    private SmsLoginAuthenticationToken(Object principal, Collection<? extends GrantedAuthority> authorities) {
        super(principal, authorities);
        setAuthenticated(Boolean.TRUE);
    }

    public SmsLoginAuthenticationToken(Object principal) {
        super(principal);
    }

    /**
     * 创建一个未认证的实例
     *
     * @param principal 手机号
     * @return SmsLoginAuthenticationToken
     */
    public static SmsLoginAuthenticationToken unauthenticated(Object principal) {
        return new SmsLoginAuthenticationToken(principal);
    }

    /**
     * 创建一个认证过的实例
     *
     * @param principal 邮箱地址
     * @return SmsLoginAuthenticationToken
     */
    public static SmsLoginAuthenticationToken authenticated(Object principal, Collection<? extends GrantedAuthority> authorities) {
		return new SmsLoginAuthenticationToken(principal, authorities);
	}

}