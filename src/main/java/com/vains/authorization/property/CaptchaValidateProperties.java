package com.vains.authorization.property;

import com.vains.authorization.constant.DefaultConstants;
import jakarta.annotation.PostConstruct;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.http.HttpMethod;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 验证码校验配置
 *
 * @author vains 2023/12/18
 */
@Data
@ConfigurationProperties(prefix = CaptchaValidateProperties.PREV)
public class CaptchaValidateProperties {

    static final String PREV = "vains.captcha";

    /**
     * 验证码认证类型和对应的地址
     */
    private Map<String, ValidateInfo> validate;

    /**
     * 初始化时合并配置
     */
    @PostConstruct
    public void mergeConfig() {
        this.initConfig();
        // 遍历配置map
        this.validate.forEach((k, v) -> {
            // 如果添加了 requestUris 配置
            if (!ObjectUtils.isEmpty(v.getRequestUris())) {
                if (ObjectUtils.isEmpty(v.getMatcherInfos())) {
                    v.setMatcherInfos(new ArrayList<>());
                }
                Set<String> existUri = v.getMatcherInfos().stream()
                        .map(MatcherInfo::getUrl)
                        .collect(Collectors.toSet());
                // 添加至
                v.getRequestUris().stream()
                        // 如果在MatcherInfo中配置过则跳过
                        .filter(uri -> !existUri.contains(uri))
                        // 转成MatcherInfo
                        .map(MatcherInfo::new)
                        .forEach(v.getMatcherInfos()::add);
            }
        });
    }

    /**
     * 添加验证码校验规则
     *
     * @param type          验证码类型
     * @param url           拦截地址
     * @param codeParameter 该类型对应的验证码参数，如果为空默认使用类型
     * @param method        被拦截地址的http 请求方式
     */
    public void addValidate(String type, String url, String codeParameter, HttpMethod method) {
        this.addValidate(type, url, codeParameter, method, type);
    }

    /**
     * 添加验证码校验规则
     *
     * @param type          验证码类型
     * @param url           拦截地址
     * @param codeParameter 该类型对应的验证码参数，如果为空默认使用类型
     * @param method        被拦截地址的http 请求方式
     * @param cacheKey      当前类型验证码在缓存中的key
     */
    public void addValidate(String type, String url, String codeParameter, HttpMethod method, String cacheKey) {
        Assert.hasLength(type, "验证码类型不能为空.");
        Assert.hasLength(url, "验证码校验的地址不能为空.");
        if (method == null) {
            method = HttpMethod.POST;
        }
        if (ObjectUtils.isEmpty(codeParameter)) {
            codeParameter = type;
        }
        MatcherInfo matcherInfo = new MatcherInfo(url, method.name());
        // 找到列表中现在存在的
        ValidateInfo info = this.validate.get(type);
        if (info != null) {
            List<MatcherInfo> matcherInfos = info.getMatcherInfos();
            if (matcherInfos == null) {
                matcherInfos = new ArrayList<>();
            }
            matcherInfos.add(matcherInfo);
            // 合并
            info.setMatcherInfos(matcherInfos);
        } else {
            info = new ValidateInfo();
            List<MatcherInfo> matcherInfos = new ArrayList<>();
            matcherInfos.add(matcherInfo);
            info.setMatcherInfos(matcherInfos);
        }
        if (!ObjectUtils.isEmpty(cacheKey)) {
            info.setCacheKey(cacheKey);
        }
        info.setCodeParameter(codeParameter);

        // 覆盖
        this.validate.put(type, info);
    }

    /**
     * 初始化配置
     */
    private void initConfig() {
        if (ObjectUtils.isEmpty(this.validate)) {
            this.validate = new LinkedHashMap<>();
        }
        // 默认登录
        String login = "/login";
        // 短信认证地址
        String smsUri = "/login/sms";
        // 邮件认证地址
        String emailUri = "/login/email";
        // 短信验证码默认缓存key
        String smsCacheKey = "phone";
        // 右键验证码默认缓存key
        String emailCacheKey = "email";

        if (!this.validate.containsKey(DefaultConstants.SMS_CAPTCHA_VALIDATE)) {
            this.addValidate(DefaultConstants.SMS_CAPTCHA_VALIDATE, smsUri, (null), (null), smsCacheKey);
        }

        if (!this.validate.containsKey(DefaultConstants.EMAIL_CAPTCHA_VALIDATE)) {
            this.addValidate(DefaultConstants.EMAIL_CAPTCHA_VALIDATE, emailUri, (null), (null), emailCacheKey);
        }

        if (!this.validate.containsKey(DefaultConstants.IMAGE_CAPTCHA_VALIDATE)) {
            this.addValidate(DefaultConstants.IMAGE_CAPTCHA_VALIDATE, login, (null), (null));
        }

    }

}