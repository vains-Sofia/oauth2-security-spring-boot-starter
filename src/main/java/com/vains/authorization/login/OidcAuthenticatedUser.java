package com.vains.authorization.login;

import org.springframework.security.oauth2.core.oidc.IdTokenClaimAccessor;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;

import java.util.Map;

/**
 * OIDC 统一用户信息
 *
 * @author vains 2023/12/29
 */
public interface OidcAuthenticatedUser extends AuthenticatedUser, IdTokenClaimAccessor {

    /**
     * Returns the claims about the user. The claims are aggregated from
     * {@link #getIdToken()} and {@link #getUserInfo()} (if available).
     * @return a {@code Map} of claims about the user
     */
    @Override
    Map<String, Object> getClaims();

    /**
     * Returns the {@link OidcUserInfo UserInfo} containing claims about the user.
     * @return the {@link OidcUserInfo} containing claims about the user.
     */
    OidcUserInfo getUserInfo();

    /**
     * Returns the {@link OidcIdToken ID Token} containing claims about the user.
     * @return the {@link OidcIdToken} containing claims about the user.
     */
    OidcIdToken getIdToken();

}
