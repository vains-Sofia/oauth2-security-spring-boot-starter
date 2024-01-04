package com.vains.authorization.basic.login;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.PortMapper;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * 抽象验证码登录配置类
 *
 * @author vains 2023/12/14
 */
public abstract class AbstractLoginFilterConfigurer<B extends HttpSecurityBuilder<B>, C extends AbstractLoginFilterConfigurer<B, C, F>, F extends AbstractAuthenticationProcessingFilter>
extends AbstractAuthenticationFilterConfigurer<B, AbstractLoginFilterConfigurer<B, C, F>, F> {

    protected UserDetailsService userDetailsService;

    private final SavedRequestAwareAuthenticationSuccessHandler defaultSuccessHandler = new SavedRequestAwareAuthenticationSuccessHandler();

    protected AuthenticationSuccessHandler successHandler = this.defaultSuccessHandler;

    protected AuthenticationFailureHandler failureHandler;

    protected AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;

    @Override
    public void init(B http) throws Exception {
        super.init(http);
        if (this.failureHandler == null) {
            loginFailureHandler(new SimpleUrlAuthenticationFailureHandler("/login?error"));
        }
        // 获取子类实现提供的provider
        AuthenticationProvider authenticationProvider = authenticationProvider(http);
        // 添加到核心配置中
        http.authenticationProvider(postProcess(authenticationProvider));

        HttpSessionSecurityContextRepository sessionRepository = new HttpSessionSecurityContextRepository();
        RequestAttributeSecurityContextRepository requestRepository = new RequestAttributeSecurityContextRepository();

        DelegatingSecurityContextRepository contextRepository = new DelegatingSecurityContextRepository(
                sessionRepository, requestRepository);

        getAuthenticationFilter().setSecurityContextRepository(contextRepository);
    }

    @Override
    public void configure(B http) throws Exception {
        PortMapper portMapper = http.getSharedObject(PortMapper.class);
        if (portMapper != null) {
            ((LoginUrlAuthenticationEntryPoint) getAuthenticationEntryPoint()).setPortMapper(portMapper);
        }

        RequestCache requestCache = http.getSharedObject(RequestCache.class);
        if (requestCache != null) {
            this.defaultSuccessHandler.setRequestCache(requestCache);
        }
        getAuthenticationFilter().setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
        getAuthenticationFilter().setAuthenticationSuccessHandler(this.successHandler);
        getAuthenticationFilter().setAuthenticationFailureHandler(this.failureHandler);
        if (this.authenticationDetailsSource != null) {
            getAuthenticationFilter().setAuthenticationDetailsSource(this.authenticationDetailsSource);
        }
        SessionAuthenticationStrategy sessionAuthenticationStrategy = http
                .getSharedObject(SessionAuthenticationStrategy.class);
        if (sessionAuthenticationStrategy != null) {
            getAuthenticationFilter().setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
        }
        RememberMeServices rememberMeServices = http.getSharedObject(RememberMeServices.class);
        if (rememberMeServices != null) {
            getAuthenticationFilter().setRememberMeServices(rememberMeServices);
        }
        getAuthenticationFilter().setSecurityContextHolderStrategy(getSecurityContextHolderStrategy());

        F filter = postProcess(getAuthenticationFilter());
        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
    }

    /**
     * 自定义验证码登录时需要提供authenticationProvider
     *
     * @param http 配置实例
     * @return AuthenticationProvider
     */
    protected abstract AuthenticationProvider authenticationProvider(B http);

    protected AbstractLoginFilterConfigurer(F authenticationFilter, String defaultLoginProcessingUrl) {
        super(authenticationFilter, defaultLoginProcessingUrl);
    }

    public AbstractLoginFilterConfigurer() {
        super();
    }


    /**
     * 设置查询用户信息的service
     *
     * @param userDetailsService 获取用户信息的service
     * @return 当前对象实例
     */
    protected C userDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
        return getSelf();
    }

    protected <T> T getBeanOrNull(Class<T> type) {
        ApplicationContext context = getBuilder().getSharedObject(ApplicationContext.class);
        if (context != null) {
            String[] names = context.getBeanNamesForType(type);
            if (names.length == 1) {
                return context.getBean(type);
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private C getSelf() {
        return (C) this;
    }

    public C securityContextRepository(SecurityContextRepository securityContextRepository) {
        getAuthenticationFilter().setSecurityContextRepository(securityContextRepository);
        return getSelf();
    }

    protected abstract RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl);

    public C loginSuccessHandler(AuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
        return getSelf();
    }

    public C loginFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
        this.failureHandler = authenticationFailureHandler;
        return getSelf();
    }

    public C loginAuthenticationDetailsSource(
            AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        this.authenticationDetailsSource = authenticationDetailsSource;
        return getSelf();
    }

}