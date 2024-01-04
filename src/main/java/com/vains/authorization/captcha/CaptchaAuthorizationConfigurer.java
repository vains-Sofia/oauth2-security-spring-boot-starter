package com.vains.authorization.captcha;

import com.vains.authorization.basic.captcha.CaptchaValidator;
import com.vains.authorization.basic.captcha.CaptchaValidatorManager;
import com.vains.authorization.handler.DefaultCaptchaAuthenticationFailureHandler;
import com.vains.authorization.property.CaptchaValidateProperties;
import com.vains.authorization.property.MatcherInfo;
import com.vains.authorization.validator.DefaultCaptchaValidatorManager;
import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.session.DisableEncodeUrlFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.ObjectUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * 验证码校验过滤器配置
 *
 * @author vains 2023/12/18
 */
public class CaptchaAuthorizationConfigurer<B extends HttpSecurityBuilder<B>>
        extends AbstractHttpConfigurer<CaptchaAuthorizationConfigurer<B>, B> {

    /**
     * 验证码配置文件
     */
    private CaptchaValidateProperties validateProperties;

    /**
     * 验证码校验管理器
     */
    private CaptchaValidatorManager captchaValidatorManager;

    /**
     * 验证码校验器列表
     */
    private List<CaptchaValidator> captchaValidators = new ArrayList<>();

    /**
     * 需要校验验证码的请求
     */
    private RequestMatcher requiresAuthenticationRequestMatcher;

    /**
     * 验证码验证失败处理
     */
    private AuthenticationFailureHandler authenticationFailureHandler;

    @Override
    public void init(B builder) throws Exception {
        super.init(builder);
        this.validateProperties = this.getBeanOrNull(CaptchaValidateProperties.class);
        // 获取验证器的类型和需要拦截的url地址
        List<String> validatorNames = new ArrayList<>();
        List<MatcherInfo> matcherRequests = new ArrayList<>();

        this.validateProperties.getValidate().forEach((k, v) -> {
            validatorNames.add(k);
            if (!ObjectUtils.isEmpty(v.getMatcherInfos())) {
                matcherRequests.addAll(v.getMatcherInfos());
            }
        });

        // 校验器加载优先级：配置类 > 注入IOC
        if (ObjectUtils.isEmpty(this.captchaValidators)) {
            // 如果没有手动设置验证码的校验器，自动根据验证码类型从ioc中获取
            ApplicationContext context = getBuilder().getSharedObject(ApplicationContext.class);
            // 先获取该类型bean的所有名字，判断ioc中是否有配置的名称
            String[] namesForType = context.getBeanNamesForType(CaptchaValidator.class);
            if (!ObjectUtils.isEmpty(namesForType)) {
                List<String> nameList = Arrays.asList(namesForType);
                validatorNames.forEach(k -> {
                    if (nameList.contains(k)) {
                        // 如果ioc中有，获取并设置至校验器列表中
                        this.captchaValidators.add(context.getBean(k, CaptchaValidator.class));
                    }
                });
            }

        }
        // 默认设置验证码校验失败处理器
        if (this.authenticationFailureHandler == null) {
            ErrorAttributes errorAttributes = this.getBeanOrNull(ErrorAttributes.class);
            // 默认验证码校验失败处理
            this.authenticationFailureHandler = new DefaultCaptchaAuthenticationFailureHandler(errorAttributes);
        }

        // 如果根据类型名称没有获取到验证码校验器就根据类型获取
        if (ObjectUtils.isEmpty(this.captchaValidators)) {
            this.captchaValidators = this.getBeans(CaptchaValidator.class);
        }

        // 验证码校验管理器
        if (this.captchaValidatorManager == null) {
            this.captchaValidatorManager = this.getBeanOrNull(CaptchaValidatorManager.class);
            if (this.captchaValidatorManager == null) {
                this.captchaValidatorManager = new DefaultCaptchaValidatorManager(this.captchaValidators);
            }
        }

        // 默认初始化验证码校验器管理器
        if (!ObjectUtils.isEmpty(this.captchaValidators)) {
            if (this.captchaValidatorManager instanceof
                    DefaultCaptchaValidatorManager defaultCaptchaValidatorManager) {
                defaultCaptchaValidatorManager.setValidators(this.captchaValidators);
            }
        }

        // 初始化验证码过滤器拦截规则
        List<RequestMatcher> requestMatchers = new ArrayList<>();
        matcherRequests.stream().map(e -> new AntPathRequestMatcher(e.getUrl(), e.getHttpMethod()))
                .forEach(requestMatchers::add);
        this.requiresAuthenticationRequestMatcher = new OrRequestMatcher(requestMatchers);
    }

    @Override
    public void configure(B builder) throws Exception {
        super.configure(builder);
        CaptchaAuthorizationFilter authFilter = new CaptchaAuthorizationFilter();
        authFilter.setCaptchaValidatorManager(this.captchaValidatorManager);
        authFilter.setAuthenticationFailureHandler(this.authenticationFailureHandler);
        authFilter.setRequiresAuthenticationRequestMatcher(this.requiresAuthenticationRequestMatcher);
        // 添加至过滤器链最前方
        builder.addFilterBefore(authFilter, DisableEncodeUrlFilter.class);
    }

    /**
     * 设置验证码验证器管理器
     *
     * @param captchaValidatorManager 新的验证码验证器
     * @return 当前配置类，可链式调用
     */
    public CaptchaAuthorizationConfigurer<B> captchaValidatorManager(CaptchaValidatorManager captchaValidatorManager) {
        this.captchaValidatorManager = captchaValidatorManager;
        return this;
    }

    /**
     * 添加验证码验证器，添加后会覆盖默认添加的验证码验证器
     *
     * @param captchaValidator 验证码验证器
     * @return 当前配置类，可链式调用
     */
    public CaptchaAuthorizationConfigurer<B> captchaValidator(CaptchaValidator captchaValidator) {
        this.captchaValidators.add(captchaValidator);
        return this;
    }

    /**
     * 添加需要验证码校验的请求，会与yml中的配置合并
     *
     * @param type          验证码类型
     * @param url           请求地址
     * @param codeParameter 验证码参数
     * @param method        请求方式{@link HttpMethod}
     * @param cacheKey      验证码id在请求头或参数中的名字
     * @return 当前配置类，可链式调用
     */
    public CaptchaAuthorizationConfigurer<B> requestMatcher(String type, String url, String codeParameter, HttpMethod method, String cacheKey) {
        this.validateProperties.addValidate(type, url, codeParameter, method, cacheKey);
        return this;
    }

    /**
     * 添加需要验证码校验的请求，会与yml中的配置合并
     * 验证码id在请求头或参数中的名字默认使用type参数
     *
     * @param type          验证码类型
     * @param url           请求地址
     * @param codeParameter 验证码参数
     * @param method        请求方式{@link HttpMethod}
     * @return 当前配置类，可链式调用
     */
    public CaptchaAuthorizationConfigurer<B> requestMatcher(String type, String url, String codeParameter, HttpMethod method) {
        this.validateProperties.addValidate(type, url, codeParameter, method, type);
        return this;
    }

    /**
     * 添加需要验证码校验的请求，会与yml中的配置合并
     * 默认拦截POST请求
     *
     * @param type          验证码类型
     * @param url           请求地址
     * @param codeParameter 验证码参数
     * @param cacheKey      验证码id在请求头或参数中的名字
     * @return 当前配置类，可链式调用
     */
    public CaptchaAuthorizationConfigurer<B> requestMatcher(String type, String url, String codeParameter, String cacheKey) {
        this.validateProperties.addValidate(type, url, codeParameter, HttpMethod.POST, cacheKey);
        return this;
    }

    /**
     * 添加需要验证码校验的请求，会与yml中的配置合并
     * 验证码id在请求头或参数中的名字默认使用type参数
     * 默认拦截POST请求
     *
     * @param type          验证码类型
     * @param url           请求地址
     * @param codeParameter 验证码参数
     * @return 当前配置类，可链式调用
     */
    public CaptchaAuthorizationConfigurer<B> requestMatcher(String type, String url, String codeParameter) {
        this.validateProperties.addValidate(type, url, codeParameter, HttpMethod.POST);
        return this;
    }

    /**
     * 添加需要验证码校验的请求，会与yml中的配置合并
     * 验证码参数名默认使用type参数
     * 验证码id在请求头或参数中的名字默认使用type参数
     * 默认拦截POST请求
     *
     * @param type 验证码类型
     * @param url  请求地址
     * @return 当前配置类，可链式调用
     */
    public CaptchaAuthorizationConfigurer<B> requestMatcher(String type, String url) {
        this.validateProperties.addValidate(type, url, type, HttpMethod.POST);
        return this;
    }

    /**
     * 验证码校验失败处理
     *
     * @param failureHandler 失败处理
     * @return 当前配置类，可链式调用
     */
    public CaptchaAuthorizationConfigurer<B> failureHandler(AuthenticationFailureHandler failureHandler) {
        this.authenticationFailureHandler = failureHandler;
        return this;
    }

    protected <O> O getBeanOrNull(Class<O> type) {
        ApplicationContext context = getBuilder().getSharedObject(ApplicationContext.class);
        if (context != null) {
            String[] names = context.getBeanNamesForType(type);
            if (names.length == 1) {
                return context.getBean(type);
            }
        }
        return null;
    }

    protected <O> List<O> getBeans(Class<O> type) {
        ApplicationContext context = getBuilder().getSharedObject(ApplicationContext.class);
        if (context != null) {
            return new ArrayList<>(context.getBeansOfType(type).values());
        }
        return null;
    }

}