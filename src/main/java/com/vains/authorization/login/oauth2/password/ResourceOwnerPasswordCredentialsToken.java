package com.vains.authorization.login.oauth2.password;

import lombok.Getter;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Resource Owner Password Credentials Grant 密码模式 token
 *
 * @author vains 2023/12/27
 */
public class ResourceOwnerPasswordCredentialsToken extends AbstractAuthenticationToken {

    @Getter
    private final AuthorizationGrantType authorizationGrantType;

    private final Authentication clientPrincipal;

    /**
     * -- GETTER --
     * Returns the requested scope(s).
     * the requested scope(s), or an empty {@code Set} if not available
     */
    @Getter
    private final Set<String> scopes;

    /**
     * -- GETTER --
     * Returns the additional parameters.
     */
    @Getter
    private final Map<String, Object> additionalParameters;

    /**
     * Constructs an {@code OAuth2ClientCredentialsAuthenticationToken} using the provided parameters.
     *
     * @param clientPrincipal the authenticated client principal
     */

    public ResourceOwnerPasswordCredentialsToken(AuthorizationGrantType authorizationGrantType,
                                                 Authentication clientPrincipal, @Nullable Set<String> scopes,
                                                 @Nullable Map<String, Object> additionalParameters) {
        super(Collections.emptyList());
        Assert.notNull(authorizationGrantType, "authorizationGrantType cannot be null");
        Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
        this.authorizationGrantType = authorizationGrantType;
        this.clientPrincipal = clientPrincipal;
        this.scopes = Collections.unmodifiableSet(scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
        this.additionalParameters = Collections.unmodifiableMap(additionalParameters != null
                ? new HashMap<>(additionalParameters) : Collections.emptyMap());
    }

    /**
     * Returns the authorization grant type.
     *
     * @return the authorization grant type
     */
    public AuthorizationGrantType getGrantType() {
        return this.authorizationGrantType;
    }

    @Override
    public Object getPrincipal() {
        return this.clientPrincipal;
    }

    @Override
    public Object getCredentials() {
        return "";
    }

}
