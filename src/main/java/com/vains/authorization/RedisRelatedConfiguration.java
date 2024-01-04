package com.vains.authorization;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vains.authorization.basic.captcha.CaptchaRepository;
import com.vains.authorization.captcha.BasicCaptcha;
import com.vains.authorization.captcha.repository.RedisCaptchaRepository;
import com.vains.authorization.property.CaptchaValidateProperties;
import com.vains.authorization.repository.RedisAuthorizationConsentRepository;
import com.vains.authorization.repository.RedisClientRepository;
import com.vains.authorization.repository.RedisOAuth2AuthorizationRepository;
import com.vains.authorization.service.RedisOAuth2AuthorizationConsentService;
import com.vains.authorization.service.RedisOAuth2AuthorizationService;
import com.vains.authorization.service.RedisRegisteredClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisKeyValueAdapter;
import org.springframework.data.redis.core.RedisOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.repository.configuration.EnableRedisRepositories;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;
import org.springframework.security.jackson2.CoreJackson2Module;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * Redis相关配置
 *
 * @author vains 2023/12/21
 */
@RequiredArgsConstructor
@Configuration(proxyBeanMethods = false)
@ConditionalOnClass(RedisOperations.class)
@EnableRedisRepositories(basePackages = {"com.vains.authorization.repository"},
        enableKeyspaceEvents = RedisKeyValueAdapter.EnableKeyspaceEvents.ON_STARTUP)
public class RedisRelatedConfiguration {

    private final Jackson2ObjectMapperBuilder builder;

    @Bean
    @ConditionalOnMissingBean
    @DependsOn("redisTemplate")
    public CaptchaRepository redisCaptchaRepository(RedisTemplate<Object, BasicCaptcha> redisTemplate,
                                                    CaptchaValidateProperties captchaValidateProperties) {
        return new RedisCaptchaRepository(redisTemplate, captchaValidateProperties);
    }

    /**
     * 默认情况下使用
     *
     * @param connectionFactory redis链接工厂
     * @return RedisTemplate
     */
    @Bean
    @ConditionalOnMissingBean
    public RedisTemplate<?, ?> redisTemplate(RedisConnectionFactory connectionFactory) {
        // 字符串序列化器
        StringRedisSerializer stringRedisSerializer = new StringRedisSerializer();

        // 创建ObjectMapper并添加默认配置
        ObjectMapper objectMapper = builder.createXmlMapper(false).build();

        // 序列化所有字段
        objectMapper.setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.ANY);

        // 此项必须配置，否则如果序列化的对象里边还有对象，会报如下错误：
        //     java.lang.ClassCastException: java.util.LinkedHashMap cannot be cast to XXX
        objectMapper.activateDefaultTyping(
                objectMapper.getPolymorphicTypeValidator(),
                ObjectMapper.DefaultTyping.NON_FINAL,
                JsonTypeInfo.As.PROPERTY);

        // 添加Security提供的Jackson Mixin
        objectMapper.registerModule(new CoreJackson2Module());

        // 存入redis时序列化值的序列化器

        return getRedisTemplate(connectionFactory, objectMapper, stringRedisSerializer);
    }

    @Bean
    @ConditionalOnMissingBean
    public RegisteredClientRepository registeredClientRepository(RedisClientRepository repository) {
        return new RedisRegisteredClientRepository(repository);
    }

    @Bean
    @ConditionalOnMissingBean
    public OAuth2AuthorizationService authorizationService(RegisteredClientRepository registeredClientRepository,
                                                           RedisOAuth2AuthorizationRepository authorizationRepository) {
        return new RedisOAuth2AuthorizationService(registeredClientRepository, authorizationRepository);
    }

    @Bean
    @ConditionalOnMissingBean
    public OAuth2AuthorizationConsentService authorizationConsentService(RegisteredClientRepository registeredClientRepository,
                                                                         RedisAuthorizationConsentRepository authorizationConsentRepository) {
        return new RedisOAuth2AuthorizationConsentService(registeredClientRepository, authorizationConsentRepository);
    }

    private static RedisTemplate<Object, Object> getRedisTemplate(RedisConnectionFactory connectionFactory, ObjectMapper objectMapper, StringRedisSerializer stringRedisSerializer) {
        Jackson2JsonRedisSerializer<Object> valueSerializer =
                new Jackson2JsonRedisSerializer<>(objectMapper, Object.class);

        RedisTemplate<Object, Object> redisTemplate = new RedisTemplate<>();

        // 设置值序列化
        redisTemplate.setValueSerializer(valueSerializer);
        // 设置hash格式数据值的序列化器
        redisTemplate.setHashValueSerializer(valueSerializer);
        // 默认的Key序列化器为：JdkSerializationRedisSerializer
        redisTemplate.setKeySerializer(stringRedisSerializer);
        // 设置字符串序列化器
        redisTemplate.setStringSerializer(stringRedisSerializer);
        // 设置hash结构的key的序列化器
        redisTemplate.setHashKeySerializer(stringRedisSerializer);

        // 设置连接工厂
        redisTemplate.setConnectionFactory(connectionFactory);
        return redisTemplate;
    }

}