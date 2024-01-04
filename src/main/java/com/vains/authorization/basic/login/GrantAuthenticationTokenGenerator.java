package com.vains.authorization.basic.login;

import com.vains.authorization.login.oauth2.password.ResourceOwnerPasswordCredentialsToken;
import org.springframework.security.authentication.AbstractAuthenticationToken;

/**
 * 自定义grant type用户认证接口
 *
 * @author vains 2023/12/28
 */
public interface GrantAuthenticationTokenGenerator {

    /**
     * 根据账号、密码生成token，根据配置的provider验证对应的token
     *
     * @param username 账号
     * @param password 密码
     * @param authenticationToken    由converter转换过的token，包含账号、密码
     * @return 认证成功后的认证信息
     */
    AbstractAuthenticationToken authenticate(String username, String password,
                                             ResourceOwnerPasswordCredentialsToken authenticationToken);

}
