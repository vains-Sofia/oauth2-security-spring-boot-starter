package com.vains.authorization.captcha.repository;

import com.vains.authorization.basic.captcha.AbstractCaptchaRepository;
import com.vains.authorization.captcha.CaptchaType;
import com.vains.authorization.captcha.BasicCaptcha;
import com.vains.authorization.property.CaptchaValidateProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.Assert;
import org.springframework.util.ObjectUtils;
import org.springframework.web.context.request.ServletWebRequest;

/**
 * 将验证码存储至session中
 *
 * @author vains 2023/12/20
 */
@Slf4j
public class SessionCaptchaRepository extends AbstractCaptchaRepository {

    /**
     * 存储至session
     */
    private static final int SCOPE = 1;

    public SessionCaptchaRepository(CaptchaValidateProperties captchaValidateProperties) {
        super(captchaValidateProperties);
    }

    @Override
    public void save(ServletWebRequest request, BasicCaptcha captcha) {
        Assert.notNull(captcha, "保存失败，验证码不能为空.");
        Assert.notNull(captcha.getType(), "保存失败，验证码类型不能为空.");
        request.setAttribute(this.getCaptchaCacheKey(request, captcha.getType()), captcha, SCOPE);
    }

    @Override
    public void remove(ServletWebRequest request, CaptchaType type) {
        if (type == null || ObjectUtils.isEmpty(type.value())) {
            log.debug("获取到空的验证码类型，不处理");
            return;
        }
        request.removeAttribute(this.getCaptchaCacheKey(request, type), SCOPE);
    }

    @Override
    public BasicCaptcha get(ServletWebRequest request, CaptchaType type) {
        Object attribute = request.getAttribute(this.getCaptchaCacheKey(request, type), SCOPE);
        if (attribute instanceof BasicCaptcha captcha) {
            // 如果是BasicCaptcha的实例，转换后直接返回
            return captcha;
        }
        log.debug("未在当前session中获取到{}类型的验证码.", type.value());
        return null;
    }

}