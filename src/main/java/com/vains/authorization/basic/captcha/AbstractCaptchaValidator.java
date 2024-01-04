package com.vains.authorization.basic.captcha;

import com.vains.authorization.property.CaptchaValidateProperties;
import com.vains.authorization.property.MatcherInfo;
import com.vains.authorization.property.ValidateInfo;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.context.request.ServletWebRequest;

import java.util.ArrayList;
import java.util.List;

/**
 * 验证码校验器抽象实现
 *
 * @author vains 2023/12/13
 */
@RequiredArgsConstructor
public abstract class AbstractCaptchaValidator implements ApplicationContextAware, CaptchaValidator {

    /**
     * 当前验证码类型在请求头中的key
     */
    @Getter
    private String cacheKey;

    /**
     * 验证码类型
     */
    @Getter
    private String validateType;

    /**
     * 请求参数key
     */
    @Getter
    private String codeParameter;

    private RequestMatcher requestMatcher;

    private final CaptchaValidateProperties captchaValidateProperties;

    /**
     * 当前请求是否需要验证码校验
     *
     * @param request 当前请求
     * @return 是否需要建议
     */
    @Override
    public boolean supports(ServletWebRequest request) {

        return this.requestMatcher.matches(request.getRequest());
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        this.validateType = applicationContext.getBeanNamesForType(this.getClass())[0];
        ValidateInfo validateInfo = this.captchaValidateProperties.getValidate()
                .get(this.getValidateType());
        Assert.notNull(validateInfo, "当前验证器的类型[" + this.validateType + "]未在yml中配置，初始化失败.");
        // 初始化requestMatcher
        List<RequestMatcher> requestMatchers = new ArrayList<>();
        for (MatcherInfo matcherInfo : validateInfo.getMatcherInfos()) {
            AntPathRequestMatcher antPathRequestMatcher = new AntPathRequestMatcher(
                    matcherInfo.getUrl(), matcherInfo.getHttpMethod());
            requestMatchers.add(antPathRequestMatcher);
        }
        this.requestMatcher = new OrRequestMatcher(requestMatchers);

        // 初始化请求头的key
        this.cacheKey = validateInfo.getCacheKey();
        // 初始化请求参数key
        this.codeParameter = validateInfo.getCodeParameter();
    }


}