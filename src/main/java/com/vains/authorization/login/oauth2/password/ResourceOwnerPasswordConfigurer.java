package com.vains.authorization.login.oauth2.password;

import com.vains.authorization.basic.login.GrantAuthenticationTokenGenerator;
import com.vains.authorization.constant.DefaultConstants;
import com.vains.authorization.util.OAuth2SecurityUtils;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;

/**
 * 密码模式配置类
 *
 * @author vains 2023/12/27
 */
public class ResourceOwnerPasswordConfigurer
        extends AbstractHttpConfigurer<ResourceOwnerPasswordConfigurer, HttpSecurity> {

    /**
     * 账号参数名
     */
    private String usernameParameter;

    /**
     * 密码参数名
     */
    private String passwordParameter;

    /**
     * 密码模式grant_type参数的值
     */
    private String passwordGrantType;

    /**
     * token生成器
     */
    private OAuth2TokenGenerator<?> tokenGenerator;

    /**
     * 身份认证实现
     */
    private AuthenticationProvider authenticationProvider;

    /**
     * 存储token信息
     */
    private OAuth2AuthorizationService authorizationService;

    /**
     * 生成身份认证token实现
     */
    private GrantAuthenticationTokenGenerator grantAuthenticationTokenGenerator;

    /**
     * 密码模式认证、生成token实现
     */
    private ResourceOwnerPasswordCredentialsProvider resourceOwnerPasswordCredentialsProvider;

    /**
     * 密码模式参数转换器
     */
    private ResourceOwnerPasswordCredentialsConverter resourceOwnerPasswordCredentialsConverter;

    @Override
    public void init(HttpSecurity builder) {
        initConverter();
        initAuthenticationProvider(builder);
        initTokenConfigurer(builder);
        initGrantType(builder);
    }

    private void initConverter() {
        if (this.resourceOwnerPasswordCredentialsConverter == null) {
            this.resourceOwnerPasswordCredentialsConverter = new ResourceOwnerPasswordCredentialsConverter();
        }
		if (!ObjectUtils.isEmpty(this.usernameParameter)) {
			this.resourceOwnerPasswordCredentialsConverter.setUsernameParameter(this.usernameParameter);
		}
		if (!ObjectUtils.isEmpty(this.passwordParameter)) {
			this.resourceOwnerPasswordCredentialsConverter.setPasswordParameter(this.passwordParameter);
		}
		if (ObjectUtils.isEmpty(this.passwordGrantType)) {
			this.passwordGrantType = DefaultConstants.GRANT_TYPE_PASSWORD;
		}
		this.resourceOwnerPasswordCredentialsConverter.setPasswordGrantType(this.passwordGrantType);
	}

	private void initAuthenticationProvider(HttpSecurity builder) {
		if (this.authenticationProvider == null) {
			DaoAuthenticationProvider daoAuthenticationProvider =
                    OAuth2SecurityUtils.getDaoAuthenticationProvider(builder);
			Assert.notNull(daoAuthenticationProvider, "获取Bean[DaoAuthenticationProvider]失败，加载密码模式失败.");
			this.authenticationProvider = daoAuthenticationProvider;
		}

		if (this.tokenGenerator == null) {
			OAuth2TokenGenerator<?> oAuth2TokenGenerator = OAuth2SecurityUtils.getTokenGenerator(builder);
			Assert.notNull(oAuth2TokenGenerator, "获取Bean[OAuth2TokenGenerator]失败，加载密码模式失败.");
			this.tokenGenerator = oAuth2TokenGenerator;
		}

		if (this.authorizationService == null) {
			OAuth2AuthorizationService oAuth2AuthorizationService =
                    OAuth2SecurityUtils.getAuthorizationService(builder);
			Assert.notNull(oAuth2AuthorizationService, "获取Bean[AuthorizationService]失败，加载密码模式失败.");
			this.authorizationService = oAuth2AuthorizationService;
		}

		if (this.resourceOwnerPasswordCredentialsProvider == null) {
			this.resourceOwnerPasswordCredentialsProvider = new ResourceOwnerPasswordCredentialsProvider(
					this.tokenGenerator, this.authenticationProvider, this.authorizationService);
		}

		if (!ObjectUtils.isEmpty(this.usernameParameter)) {
			this.resourceOwnerPasswordCredentialsProvider.setUsernameParameter(this.usernameParameter);
		}
		if (!ObjectUtils.isEmpty(this.passwordParameter)) {
			this.resourceOwnerPasswordCredentialsProvider.setPasswordParameter(this.passwordParameter);
		}

		if (this.grantAuthenticationTokenGenerator != null) {
			this.resourceOwnerPasswordCredentialsProvider
                    .setGrantAuthenticationTokenGenerator(this.grantAuthenticationTokenGenerator);
		}
	}

	private void initTokenConfigurer(HttpSecurity builder) {
		OAuth2AuthorizationServerConfigurer configurer =
                builder.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
		Assert.notNull(configurer, "请在认证服务配置中加载该配置.");
		// 添加自定义grant_type——密码模式登录
		configurer.tokenEndpoint(tokenEndpoint -> tokenEndpoint
                .accessTokenRequestConverter(this.resourceOwnerPasswordCredentialsConverter)
                .authenticationProvider(this.resourceOwnerPasswordCredentialsProvider)
		);
	}

	private void initGrantType(HttpSecurity builder) {
		OAuth2AuthorizationServerConfigurer configurer =
                builder.getConfigurer(OAuth2AuthorizationServerConfigurer.class);
		Assert.notNull(configurer, "请在认证服务配置中加载该配置.");
		configurer
                // 开启OpenID Connect 1.0协议相关端点
                .oidc(oidcConfigurer -> oidcConfigurer
                        .providerConfigurationEndpoint(provider -> provider
                                .providerConfigurationCustomizer(c -> c
                                        // 为OIDC端点添加密码的登录方式
                                        .grantType(this.passwordGrantType)
						)
				)
		)
                // 让认证服务器元数据中有自定义的认证方式
                .authorizationServerMetadataEndpoint(metadata -> metadata
                        .authorizationServerMetadataCustomizer(customizer -> customizer
                                // 添加密码模式
                                .grantType(this.passwordGrantType)
				)
		);
	}

	public ResourceOwnerPasswordConfigurer usernameParameter(String usernameParameter) {
		this.usernameParameter = usernameParameter;
		return this;
	}

	public ResourceOwnerPasswordConfigurer passwordParameter(String passwordParameter) {
		this.passwordParameter = passwordParameter;
		return this;
	}

	public ResourceOwnerPasswordConfigurer passwordGrantType(String passwordGrantType) {
		this.passwordGrantType = passwordGrantType;
		return this;
	}

	public ResourceOwnerPasswordConfigurer tokenGenerator(OAuth2TokenGenerator<?> tokenGenerator) {
		this.tokenGenerator = tokenGenerator;
		return this;
	}

	public ResourceOwnerPasswordConfigurer authenticationProvider(AuthenticationProvider authenticationProvider) {
		this.authenticationProvider = authenticationProvider;
		return this;
	}

	public ResourceOwnerPasswordConfigurer authorizationService(OAuth2AuthorizationService authorizationService) {
		this.authorizationService = authorizationService;
		return this;
	}

	public ResourceOwnerPasswordConfigurer grantAuthenticationTokenGenerator(
			GrantAuthenticationTokenGenerator grantAuthenticationTokenGenerator) {
		this.grantAuthenticationTokenGenerator = grantAuthenticationTokenGenerator;
		return this;
	}

}
