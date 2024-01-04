package com.vains.authorization.basic.login;

import com.vains.authorization.exception.InvalidCaptchaException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * 抽象验证码登录校验
 *
 * @author vains 2023/12/15
 */
@Slf4j
@RequiredArgsConstructor
public abstract class AbstractCaptchaLoginAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;

    protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

    protected UserDetailsChecker authenticationChecks = new AccountStatusUserDetailsChecker();

    /**
     * 获取认证信息中的账号(手机/邮箱)
     *
     * @param authentication 认证信息
     * @return 账号(手机 / 邮箱)
     */
    private String determineUsername(Authentication authentication) {
        return (authentication.getPrincipal() == null) ? "NONE_PROVIDED" : authentication.getName();
    }

    /**
     * 根据当前请求校验验证码
     *
     * @param request 当前请求实例
     * @throws AuthenticationException 如果校验失败需抛出{@link AuthenticationException}或子异常
     */
    protected void additionalAuthenticationChecks(HttpServletRequest request) throws AuthenticationException {
        // 默认不做处理
    }

    /**
     * 获取用户信息
     *
     * @param authentication 过滤器中转换的AbstractCaptchaAuthenticationToken实例
     * @return 用户信息
     */
    protected UserDetails loadUserDetails(Authentication authentication) {
        Assert.isInstanceOf(AbstractCaptchaAuthenticationToken.class, authentication,
                            () -> this.messages.getMessage("AbstractUserDetailsAuthenticationProvider.onlySupports",
                                                           "Only AbstractCaptchaAuthenticationToken is supported"));
        // 获取账号
        String username = determineUsername(authentication);
        try {
            // 获取当前request
            RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
            if (requestAttributes == null) {
                throw new InvalidCaptchaException("Failed to get the current request.");
            }
            HttpServletRequest request = ((ServletRequestAttributes) requestAttributes).getRequest();
            // 校验验证码
            this.additionalAuthenticationChecks(request);

            // 获取用户信息
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            if (userDetails == null) {
                throw new InternalAuthenticationServiceException(
                        "UserDetailsService returned null, which is an interface contract violation");
            }

            // 检测用户信息
            authenticationChecks.check(userDetails);

            return userDetails;
        } catch (UsernameNotFoundException ex) {
            log.debug("Failed to find user '" + username + "'");
            throw new BadCredentialsException(this.messages
                    .getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
        }
    }

}