package com.vains.authorization.validator;

import com.vains.authorization.basic.captcha.AbstractCaptchaValidator;
import com.vains.authorization.basic.captcha.CaptchaRepository;
import com.vains.authorization.captcha.CaptchaType;
import com.vains.authorization.property.CaptchaValidateProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.context.request.ServletWebRequest;

/**
 * 图形验证码校验
 *
 * @author vains 2023/12/14
 */
@Slf4j
public class EmailCaptchaValidator extends AbstractCaptchaValidator {

    private final DefaultCommonValidator validator;

    public EmailCaptchaValidator(CaptchaRepository captchaRepository,
                                 CaptchaValidateProperties captchaValidateProperties) {
        super(captchaValidateProperties);
        this.validator = new DefaultCommonValidator(captchaRepository);
    }

    @Override
    public void validate(ServletWebRequest request) {
        validator.validate(request, this.getCodeParameter(), new CaptchaType(this.getValidateType()));
        log.debug("地址[{}]的邮箱验证码校验通过.", request.getRequest().getRequestURI());
    }

}