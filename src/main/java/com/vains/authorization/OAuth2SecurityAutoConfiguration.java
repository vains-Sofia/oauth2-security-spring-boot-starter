package com.vains.authorization;

import com.vains.authorization.basic.captcha.CaptchaRepository;
import com.vains.authorization.basic.captcha.CaptchaValidator;
import com.vains.authorization.basic.captcha.CaptchaValidatorManager;
import com.vains.authorization.captcha.repository.SessionCaptchaRepository;
import com.vains.authorization.constant.DefaultConstants;
import com.vains.authorization.property.CaptchaValidateProperties;
import com.vains.authorization.validator.DefaultCaptchaValidatorManager;
import com.vains.authorization.validator.EmailCaptchaValidator;
import com.vains.authorization.validator.ImageCaptchaValidator;
import com.vains.authorization.validator.SmsCaptchaValidator;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingClass;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.util.List;
import java.util.UUID;

/**
 * 自动配置类
 *
 * @author vains 2023/12/21
 */
@AutoConfiguration
@RequiredArgsConstructor
public class OAuth2SecurityAutoConfiguration {

	private final CaptchaValidateProperties captchaValidateProperties;

	@Bean(DefaultConstants.SMS_CAPTCHA_VALIDATE)
    @ConditionalOnMissingBean(name = DefaultConstants.SMS_CAPTCHA_VALIDATE)
    public CaptchaValidator smsCaptchaValidator(CaptchaRepository captchaRepository) {
		return new SmsCaptchaValidator(captchaRepository, captchaValidateProperties);
	}

	@Bean(DefaultConstants.EMAIL_CAPTCHA_VALIDATE)
    @ConditionalOnMissingBean(name = DefaultConstants.EMAIL_CAPTCHA_VALIDATE)
    public CaptchaValidator emailCaptchaValidator(CaptchaRepository captchaRepository) {
		return new EmailCaptchaValidator(captchaRepository, captchaValidateProperties);
	}

	@Bean(DefaultConstants.IMAGE_CAPTCHA_VALIDATE)
    @ConditionalOnMissingBean(name = DefaultConstants.IMAGE_CAPTCHA_VALIDATE)
    public CaptchaValidator imageCaptchaValidator(CaptchaRepository captchaRepository) {
		return new ImageCaptchaValidator(captchaRepository, captchaValidateProperties);
	}

	@Bean
    @ConditionalOnMissingBean
    public CaptchaValidatorManager captchaValidatorManager(List<CaptchaValidator> validators) {
		return new DefaultCaptchaValidatorManager(validators);
	}

	@Bean
    @ConditionalOnMissingBean
    @ConditionalOnMissingClass("org.springframework.data.redis.core.RedisTemplate")
    public CaptchaRepository sessionCaptchaRepository(CaptchaValidateProperties captchaValidateProperties) {
		return new SessionCaptchaRepository(captchaValidateProperties);
	}

	/* Authorization Server */

	/**
     * 将AuthenticationManager注入ioc中，其它需要使用地方可以直接从ioc中获取
     *
     * @param authenticationConfiguration 导出认证配置
     * @return AuthenticationManager 认证管理器
     */
    @Bean
    @SneakyThrows
    @ConditionalOnMissingBean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) {
		return authenticationConfiguration.getAuthenticationManager();
	}

	/**
     * 配置密码解析器，使用BCrypt的方式对密码进行加密和验证
     *
     * @return BCryptPasswordEncoder
     */
    @Bean
    @ConditionalOnMissingBean
    public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	/**
     * 配置客户端Repository
     *
     * @param passwordEncoder 密码解析器
     * @return 基于数据库的repository
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnMissingClass("org.springframework.data.redis.core.RedisTemplate")
    public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {
		RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                // 客户端id
                .clientId(UUID.randomUUID().toString())
                // 客户端秘钥，使用密码解析器加密
                .clientSecret(passwordEncoder.encode("123456"))
                // 客户端认证方式，基于请求头的认证
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                // 配置资源服务器使用该客户端获取授权时支持的方式
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN).authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).authorizationGrantType(new AuthorizationGrantType(DefaultConstants.GRANT_TYPE_PASSWORD))
                // 授权码模式回调地址，oauth2.1已改为精准匹配，不能只设置域名，并且屏蔽了localhost，本机使用127.0.0.1访问
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc").redirectUri("https://www.baidu.com")
                // 该客户端的授权范围，OPENID与PROFILE是IdToken的scope，获取授权时请求OPENID的scope时认证服务会返回IdToken
                .scope(OidcScopes.OPENID).scope(OidcScopes.PROFILE)
                // 自定scope
                .scope("message.read").scope("message.write")
                // 客户端设置，设置用户需要确认授权
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build()).tokenSettings(TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.REFERENCE).build()).build();
		// 生成一个默认客户端，防止报错
		return new InMemoryRegisteredClientRepository(registeredClient);
	}

	/**
     * 配置基于内存的oauth2的授权管理服务
     *
     * @return InMemoryOAuth2AuthorizationService
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnMissingClass("org.springframework.data.redis.core.RedisTemplate")
    public OAuth2AuthorizationService authorizationService() {
		// 基于内存的oauth2认证服务
		return new InMemoryOAuth2AuthorizationService();
	}

	/**
     * 配置基于内存的授权确认管理服务
     *
     * @return InMemoryOAuth2AuthorizationConsentService
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnMissingClass("org.springframework.data.redis.core.RedisTemplate")
    public OAuth2AuthorizationConsentService authorizationConsentService() {
		// 基于内存的授权确认管理服务
		return new InMemoryOAuth2AuthorizationConsentService();
	}

}