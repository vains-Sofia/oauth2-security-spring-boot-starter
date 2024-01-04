package com.vains.authorization.login.oauth2.password;

import com.vains.authorization.basic.login.GrantAuthenticationTokenGenerator;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

/**
 * 默认账号密码认证
 *
 * @author vains 2023/12/28
 */
public class DefaultGrantAuthenticationTokenGenerator implements GrantAuthenticationTokenGenerator {

    @Override
    public AbstractAuthenticationToken authenticate(String username, String password,
                                                    ResourceOwnerPasswordCredentialsToken authenticationToken) {
        return UsernamePasswordAuthenticationToken.unauthenticated(username, password);
    }
}
