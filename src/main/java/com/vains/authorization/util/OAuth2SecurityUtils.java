package com.vains.authorization.util;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.Map;
import java.util.Set;

/**
 * 工具类
 *
 * @author vains 2023/12/27
 */
@Slf4j
public class OAuth2SecurityUtils {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

	private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE = new OAuth2TokenType(OidcParameterNames.ID_TOKEN);

	/**
     * 提取请求中的参数并转为一个map返回
     *
     * @param request 当前请求
     * @return 请求中的参数
     */
    public static MultiValueMap<String, String> getParameters(HttpServletRequest request) {
		Map<String, String[]> parameterMap = request.getParameterMap();
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
		parameterMap.forEach((key, values) -> {
			for (String value : values) {
				parameters.add(key, value);
			}
		});
		return parameters;
	}

	/**
     * 抛出 OAuth2AuthenticationException 异常
     *
     * @param errorCode 错误码
     * @param message   错误信息
     * @param errorUri  错误对照地址
     */
    public static void throwError(String errorCode, String message, String errorUri) {
		OAuth2Error error = new OAuth2Error(errorCode, message, errorUri);
		throw new OAuth2AuthenticationException(error);
	}

	/**
     * 从认证信息中获取客户端token
     *
     * @param authentication 认证信息
     * @return 客户端认证信息，获取失败抛出异常
     */
    public static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
		OAuth2ClientAuthenticationToken clientPrincipal = null;
		if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
			clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
		}
		if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
			return clientPrincipal;
		}
		throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	public static OAuth2AccessToken generateAccessToken(OAuth2TokenGenerator<?> tokenGenerator,
														OAuth2Authorization.Builder authorizationBuilder,
														DefaultOAuth2TokenContext.Builder tokenContextBuilder) {
		OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
		OAuth2Token generatedAccessToken = tokenGenerator.generate(tokenContext);
		if (generatedAccessToken == null) {
			OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
												"The token generator failed to generate the access token.", ERROR_URI);
			throw new OAuth2AuthenticationException(error);
		}

		if (log.isTraceEnabled()) {
			log.trace("Generated access token");
		}
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
															  generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
															  generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());
		if (generatedAccessToken instanceof ClaimAccessor) {
			authorizationBuilder.token(accessToken, (metadata) ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, ((ClaimAccessor) generatedAccessToken).getClaims()));
		} else {
			authorizationBuilder.accessToken(accessToken);
		}
		return accessToken;
	}

	public static OAuth2RefreshToken generateRefreshToken(RegisteredClient registeredClient,
														  OAuth2TokenGenerator<?> tokenGenerator,
														  OAuth2ClientAuthenticationToken clientPrincipal,
														  OAuth2Authorization.Builder authorizationBuilder,
														  DefaultOAuth2TokenContext.Builder tokenContextBuilder) {
		OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
		OAuth2RefreshToken refreshToken = null;
		if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN) &&
			// Do not issue refresh token to public client
			!clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {

			OAuth2Token generatedRefreshToken = tokenGenerator.generate(tokenContext);
			if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
													"The token generator failed to generate the refresh token.", ERROR_URI);
				throw new OAuth2AuthenticationException(error);
			}

				if (log.isTraceEnabled()) {
					log.trace("Generated refresh token");
				}
				refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
				authorizationBuilder.refreshToken(refreshToken);
		}
		return refreshToken;
	}

	public static OidcIdToken generateIdToken(Set<String> authorizedScopes,
											  OAuth2TokenGenerator<?> tokenGenerator,
											  OAuth2Authorization.Builder authorizationBuilder,
											  DefaultOAuth2TokenContext.Builder tokenContextBuilder) {
		OidcIdToken idToken;
		OAuth2TokenContext tokenContext = tokenContextBuilder
                .tokenType(ID_TOKEN_TOKEN_TYPE)
                // ID token customizer may need access to the access token and/or refresh token
                .authorization(authorizationBuilder.build())
                .build();
		if (authorizedScopes.contains(OidcScopes.OPENID)) {
			// @formatter:on
			OAuth2Token generatedIdToken = tokenGenerator.generate(tokenContext);
			if (!(generatedIdToken instanceof Jwt)) {
				OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
													"The token generator failed to generate the ID token.", ERROR_URI);
				throw new OAuth2AuthenticationException(error);
			}

			if (log.isTraceEnabled()) {
				log.trace("Generated id token");
			}

			idToken = new OidcIdToken(generatedIdToken.getTokenValue(), generatedIdToken.getIssuedAt(),
									  generatedIdToken.getExpiresAt(), ((Jwt) generatedIdToken).getClaims());
			authorizationBuilder.token(idToken, (metadata) ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims()));
		} else {
			idToken = null;
		}
		return idToken;
	}

	public static  <T> T getBeanOrNull(HttpSecurityBuilder<?> builder, Class<T> type) {
		ApplicationContext context = builder.getSharedObject(ApplicationContext.class);
		if (context != null) {
			String[] names = context.getBeanNamesForType(type);
			if (names.length == 1) {
				return context.getBean(type);
			}
		}
		return null;
	}

	public static OAuth2TokenGenerator<? extends OAuth2Token> getTokenGenerator(HttpSecurity httpSecurity) {
		OAuth2TokenGenerator<?> tokenGenerator = httpSecurity.getSharedObject(OAuth2TokenGenerator.class);
		if (tokenGenerator == null) {
			tokenGenerator = getOptionalBean(httpSecurity, OAuth2TokenGenerator.class);
			if (tokenGenerator == null) {
				JwtGenerator jwtGenerator = getJwtGenerator(httpSecurity);
				OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
				OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer = getAccessTokenCustomizer(httpSecurity);
				if (accessTokenCustomizer != null) {
					accessTokenGenerator.setAccessTokenCustomizer(accessTokenCustomizer);
				}
				OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
				if (jwtGenerator != null) {
					tokenGenerator = new DelegatingOAuth2TokenGenerator(
							jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
				} else {
					tokenGenerator = new DelegatingOAuth2TokenGenerator(
							accessTokenGenerator, refreshTokenGenerator);
				}
			}
			httpSecurity.setSharedObject(OAuth2TokenGenerator.class, tokenGenerator);
		}
		return tokenGenerator;
	}

	public static <T> T getOptionalBean(HttpSecurity httpSecurity, Class<T> type) {
		Map<String, T> beansMap = BeanFactoryUtils.beansOfTypeIncludingAncestors(
				httpSecurity.getSharedObject(ApplicationContext.class), type);
		if (beansMap.size() > 1) {
			throw new NoUniqueBeanDefinitionException(type, beansMap.size(),
													  "Expected single matching bean of type '" + type.getName() + "' but found " +
													  beansMap.size() + ": " + StringUtils.collectionToCommaDelimitedString(beansMap.keySet()));
		}
		return (!beansMap.isEmpty() ? beansMap.values().iterator().next() : null);
	}

	public static OAuth2TokenCustomizer<OAuth2TokenClaimsContext> getAccessTokenCustomizer(HttpSecurity httpSecurity) {
		ResolvableType type = ResolvableType.forClassWithGenerics(OAuth2TokenCustomizer.class, OAuth2TokenClaimsContext.class);
		return getOptionalBean(httpSecurity, type);
	}

	@SuppressWarnings("unchecked")
    public static <T> T getOptionalBean(HttpSecurity httpSecurity, ResolvableType type) {
		ApplicationContext context = httpSecurity.getSharedObject(ApplicationContext.class);
		String[] names = context.getBeanNamesForType(type);
		if (names.length > 1) {
			throw new NoUniqueBeanDefinitionException(type, names);
		}
		return names.length == 1 ? (T) context.getBean(names[0]) : null;
	}

	public static JwtGenerator getJwtGenerator(HttpSecurity httpSecurity) {
		JwtGenerator jwtGenerator = httpSecurity.getSharedObject(JwtGenerator.class);
		if (jwtGenerator == null) {
			JwtEncoder jwtEncoder = getJwtEncoder(httpSecurity);
			if (jwtEncoder != null) {
				jwtGenerator = new JwtGenerator(jwtEncoder);
				OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer = getJwtCustomizer(httpSecurity);
				if (jwtCustomizer != null) {
					jwtGenerator.setJwtCustomizer(jwtCustomizer);
				}
				httpSecurity.setSharedObject(JwtGenerator.class, jwtGenerator);
			}
		}
		return jwtGenerator;
	}

	public static JwtEncoder getJwtEncoder(HttpSecurity httpSecurity) {
		JwtEncoder jwtEncoder = httpSecurity.getSharedObject(JwtEncoder.class);
		if (jwtEncoder == null) {
			jwtEncoder = getOptionalBean(httpSecurity, JwtEncoder.class);
			if (jwtEncoder == null) {
				JWKSource<SecurityContext> jwkSource = getJwkSource(httpSecurity);
				if (jwkSource != null) {
					jwtEncoder = new NimbusJwtEncoder(jwkSource);
				}
			}
			if (jwtEncoder != null) {
				httpSecurity.setSharedObject(JwtEncoder.class, jwtEncoder);
			}
		}
		return jwtEncoder;
	}

	public static OAuth2TokenCustomizer<JwtEncodingContext> getJwtCustomizer(HttpSecurity httpSecurity) {
		ResolvableType type = ResolvableType.forClassWithGenerics(OAuth2TokenCustomizer.class, JwtEncodingContext.class);
		return getOptionalBean(httpSecurity, type);
	}

	public static JWKSource<SecurityContext> getJwkSource(HttpSecurity httpSecurity) {
		@SuppressWarnings("unchecked")
        JWKSource<SecurityContext> jwkSource = httpSecurity.getSharedObject(JWKSource.class);
		if (jwkSource == null) {
			ResolvableType type = ResolvableType.forClassWithGenerics(JWKSource.class, SecurityContext.class);
			jwkSource = getOptionalBean(httpSecurity, type);
			if (jwkSource != null) {
				httpSecurity.setSharedObject(JWKSource.class, jwkSource);
			}
		}
		return jwkSource;
	}

	public static OAuth2AuthorizationService getAuthorizationService(HttpSecurity httpSecurity) {
		OAuth2AuthorizationService authorizationService = httpSecurity.getSharedObject(OAuth2AuthorizationService.class);
		if (authorizationService == null) {
			authorizationService = getOptionalBean(httpSecurity, OAuth2AuthorizationService.class);
			if (authorizationService == null) {
				authorizationService = new InMemoryOAuth2AuthorizationService();
			}
			httpSecurity.setSharedObject(OAuth2AuthorizationService.class, authorizationService);
		}
		return authorizationService;
	}

	public static DaoAuthenticationProvider getDaoAuthenticationProvider(HttpSecurity httpSecurity) {
		DaoAuthenticationProvider authenticationProvider = httpSecurity.getSharedObject(DaoAuthenticationProvider.class);
		if (authenticationProvider == null) {
			authenticationProvider = getOptionalBean(httpSecurity, DaoAuthenticationProvider.class);
			if (authenticationProvider == null) {
				authenticationProvider = new DaoAuthenticationProvider();
				// 从ioc中获取passwordEncoder和UserDetailsService
				UserDetailsService uds = getBeanOrNull(httpSecurity, UserDetailsService.class);
				authenticationProvider.setUserDetailsService(uds);
				PasswordEncoder passwordEncoder = getBeanOrNull(httpSecurity, PasswordEncoder.class);
				authenticationProvider.setPasswordEncoder(passwordEncoder);
			}
			httpSecurity.setSharedObject(DaoAuthenticationProvider.class, authenticationProvider);
		}
		return authenticationProvider;
	}

}
