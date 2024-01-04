package com.vains.authorization.login.oauth2.password;

import com.vains.authorization.basic.login.GrantAuthenticationTokenGenerator;
import com.vains.authorization.constant.DefaultConstants;
import com.vains.authorization.util.OAuth2SecurityUtils;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;

import java.security.Principal;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Resource Owner passwordParameter Credentials Grant 密码模式认证提供
 *
 * @author vains 2023/12/27
 */
@Slf4j
public class ResourceOwnerPasswordCredentialsProvider implements AuthenticationProvider {

	/**
     * token生成器
     */
    private final OAuth2TokenGenerator<?> tokenGenerator;

	/**
     * 身份认证，根据提供的token进行认证
     * 默认是{@link org.springframework.security.authentication.dao.DaoAuthenticationProvider}
     */
    private final AuthenticationProvider authenticationProvider;

	/**
     * 存储oauth2登录时的认证、客户端、token等信息
     */
    private final OAuth2AuthorizationService authorizationService;

	/**
     * 账号参数名
     */
    @Setter
    private String usernameParameter = DefaultConstants.OAUTH_PARAMETER_NAME_USERNAME;

	/**
     * 密码参数名
     */
    @Setter
    private String passwordParameter = DefaultConstants.OAUTH_PARAMETER_NAME_PASSWORD;

	/**
     * 身份认证逻辑
     */
    @Setter
    private GrantAuthenticationTokenGenerator grantAuthenticationTokenGenerator =
            new DefaultGrantAuthenticationTokenGenerator();

	public ResourceOwnerPasswordCredentialsProvider(OAuth2TokenGenerator<?> tokenGenerator,
													AuthenticationProvider authenticationProvider,
													OAuth2AuthorizationService authorizationService) {
		Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(authenticationProvider, "authenticationProvider cannot be null");

		this.tokenGenerator = tokenGenerator;
		this.authorizationService = authorizationService;
		this.authenticationProvider = authenticationProvider;
	}

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

	@Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		ResourceOwnerPasswordCredentialsToken authenticationToken =
                (ResourceOwnerPasswordCredentialsToken) authentication;

		// Ensure the client is authenticated
		OAuth2ClientAuthenticationToken clientPrincipal =
                OAuth2SecurityUtils.getAuthenticatedClientElseThrowInvalidClient(authenticationToken);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
		// Ensure the client is configured to use this authorization grant type
		if (registeredClient == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, "客户端认证失败.", (null));
			throw new OAuth2AuthenticationException(error);
		}
		if (!registeredClient.getAuthorizationGrantTypes()
                .contains(authenticationToken.getAuthorizationGrantType())) {
			OAuth2SecurityUtils.throwError(
					OAuth2ErrorCodes.UNAUTHORIZED_CLIENT,
					"客户端[" + registeredClient.getClientId() + "]不支持grant_type：["
					+ authenticationToken.getGrantType().getValue() + "]",
					(null));
		}

		// 验证scope
		Set<String> authorizedScopes = getAuthorizedScopes(registeredClient, authenticationToken.getScopes());

		// 进行身份认证
		Authentication authenticate = getAuthenticatedUser(authenticationToken);

		// 以下内容摘抄自OAuth2AuthorizationCodeAuthenticationProvider
		DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
                .registeredClient(registeredClient)
                .principal(authenticate)
                .authorizationServerContext(AuthorizationServerContextHolder.getContext())
                .authorizedScopes(authorizedScopes)
                .authorizationGrantType(authenticationToken.getAuthorizationGrantType())
                .authorizationGrant(authenticationToken);

		// Initialize the OAuth2Authorization
		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
                // 存入授权scope
                .authorizedScopes(authorizedScopes)
                // 当前授权用户名称
                .principalName(authenticate.getName())
                // 设置当前用户认证信息
                .attribute(Principal.class.getName(), authenticate)
                .authorizationGrantType(authenticationToken.getAuthorizationGrantType());

		// ----- Access token -----
		OAuth2AccessToken accessToken = OAuth2SecurityUtils.generateAccessToken(
				this.tokenGenerator, authorizationBuilder, tokenContextBuilder);

		// ----- Refresh token -----
		OAuth2RefreshToken refreshToken = OAuth2SecurityUtils.generateRefreshToken(
				registeredClient, tokenGenerator, clientPrincipal, authorizationBuilder, tokenContextBuilder);

		// ----- ID token -----
		OidcIdToken idToken = OAuth2SecurityUtils.generateIdToken(
				authorizedScopes, tokenGenerator, authorizationBuilder, tokenContextBuilder);

		OAuth2Authorization authorization = authorizationBuilder.build();

		// Save the OAuth2Authorization
		this.authorizationService.save(authorization);

		Map<String, Object> additionalParameters = new HashMap<>(1);
		if (idToken != null) {
			// 放入idToken
			additionalParameters.put(OidcParameterNames.ID_TOKEN, idToken.getTokenValue());
		}

		return new OAuth2AccessTokenAuthenticationToken(
				registeredClient, clientPrincipal, accessToken, refreshToken, additionalParameters);
	}

	/**
     * 获取认证过的scope
     *
     * @param registeredClient 客户端
     * @param requestedScopes  请求中的scope
     * @return 认证过的scope
     */
    private Set<String> getAuthorizedScopes(RegisteredClient registeredClient, Set<String> requestedScopes) {
		// Default to configured scopes
		Set<String> authorizedScopes = registeredClient.getScopes();
		if (!ObjectUtils.isEmpty(requestedScopes)) {
			Set<String> unauthorizedScopes = requestedScopes.stream()
                    .filter(requestedScope -> !registeredClient.getScopes().contains(requestedScope))
                    .collect(Collectors.toSet());
			if (!ObjectUtils.isEmpty(unauthorizedScopes)) {
				OAuth2SecurityUtils.throwError(
						OAuth2ErrorCodes.INVALID_REQUEST,
						"OAuth 2.0 Parameter: " + OAuth2ParameterNames.SCOPE,
						ERROR_URI);
			}

			authorizedScopes = new LinkedHashSet<>(requestedScopes);
		}

		if (log.isTraceEnabled()) {
			log.trace("Validated token request parameters");
		}
		return authorizedScopes;
	}

	/**
     * 获取认证过的用户信息
     *
     * @param authenticationToken converter构建的认证信息，这里是包含手机号与验证码的
     * @return 认证信息
     */
    public Authentication getAuthenticatedUser(ResourceOwnerPasswordCredentialsToken authenticationToken) {
		// 获取手机号密码
		Map<String, Object> additionalParameters = authenticationToken.getAdditionalParameters();
		String usernameParameter = (String) additionalParameters.get(this.usernameParameter);
		String passwordParameter = (String) additionalParameters.get(this.passwordParameter);
		// 构建UsernamePasswordAuthenticationToken通过DaoAuthenticationProvider认证
		AbstractAuthenticationToken abstractAuthenticationToken =
                grantAuthenticationTokenGenerator.authenticate(usernameParameter, passwordParameter, authenticationToken);

		Authentication authenticate = null;
		try {
			authenticate = authenticationProvider.authenticate(abstractAuthenticationToken);
		} catch (Exception e) {
			OAuth2SecurityUtils.throwError(
					OAuth2ErrorCodes.INVALID_REQUEST,
					"认证失败：账号或密码错误.",
					ERROR_URI
			);
		}
		return authenticate;
	}

	@Override
    public boolean supports(Class<?> authentication) {
		return ResourceOwnerPasswordCredentialsToken.class.isAssignableFrom(authentication);
	}
}
