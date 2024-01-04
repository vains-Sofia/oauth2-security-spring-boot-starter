package com.vains.authorization.validator;

import com.vains.authorization.basic.captcha.CaptchaRepository;
import com.vains.authorization.captcha.CaptchaType;
import com.vains.authorization.exception.InvalidCaptchaException;
import com.vains.authorization.captcha.BasicCaptcha;
import lombok.RequiredArgsConstructor;
import org.springframework.util.ObjectUtils;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.context.request.ServletWebRequest;

import java.util.Objects;

/**
 * 默认通用校验器
 *
 * @author vains 2023/12/22
 */
@RequiredArgsConstructor
public class DefaultCommonValidator {

    private final CaptchaRepository captchaRepository;

    public void validate(ServletWebRequest request, String codeParameter, CaptchaType type) {
        // 获取请求中携带的验证码
        String codeInRequest;
        try {
            codeInRequest = ServletRequestUtils.getStringParameter(request.getRequest(), codeParameter);
        } catch (ServletRequestBindingException e) {
            throw new InvalidCaptchaException("获取验证码参数失败.");
        }
        if (ObjectUtils.isEmpty(codeInRequest)) {
            throw new InvalidCaptchaException("验证码不能为空");
        }
        // 根据类型获取缓存的验证码
        BasicCaptcha cacheCaptcha = captchaRepository.get(request, type);

        if (cacheCaptcha == null || cacheCaptcha.isExpired()) {
            captchaRepository.remove(request, type);
            throw new InvalidCaptchaException("验证码已过期，请刷新重试");
        }

        if (!Objects.equals(cacheCaptcha.getCode(), codeInRequest)) {
            throw new InvalidCaptchaException("验证码错误");
        }

    }

}