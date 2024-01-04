package com.vains.authorization.captcha.repository;

import com.vains.authorization.basic.captcha.AbstractCaptchaRepository;
import com.vains.authorization.captcha.BasicCaptcha;
import com.vains.authorization.captcha.CaptchaType;
import com.vains.authorization.property.CaptchaValidateProperties;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.util.Assert;
import org.springframework.web.context.request.ServletWebRequest;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.concurrent.TimeUnit;

/**
 * 将验证码存储至 redis 中
 *
 * @author vains 2023/12/20
 */
public class RedisCaptchaRepository extends AbstractCaptchaRepository {

    private final RedisTemplate<Object, BasicCaptcha> redisTemplate;

    public RedisCaptchaRepository(RedisTemplate<Object, BasicCaptcha> redisTemplate,
                                  CaptchaValidateProperties captchaValidateProperties) {
        super(captchaValidateProperties);
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void save(ServletWebRequest request, BasicCaptcha captcha) {
        Assert.notNull(captcha, "保存失败，验证码不能为空.");
        Assert.notNull(captcha.getType(), "保存失败，验证码类型不能为空.");
        String captchaRedisKey = this.getCaptchaCacheKey(request, captcha.getType());
        // 过期时间
        LocalDateTime expireTime = captcha.getExpireTime();
        // 获取现在至过期时间的时间差
        long seconds = Duration.between(LocalDateTime.now(), expireTime).getSeconds();
        // 过期时间5分钟后失效
        long timeout = seconds + (5 * 60);
        redisTemplate.opsForValue().set(captchaRedisKey, captcha, timeout, TimeUnit.SECONDS);
    }

    @Override
    public void remove(ServletWebRequest request, CaptchaType type) {
        String captchaRedisKey = this.getCaptchaCacheKey(request, type);
        Boolean hasKey = redisTemplate.hasKey(captchaRedisKey);
        if (hasKey != null && hasKey) {
            redisTemplate.delete(captchaRedisKey);
        }
    }

    @Override
    public BasicCaptcha get(ServletWebRequest request, CaptchaType type) {
        String captchaRedisKey = this.getCaptchaCacheKey(request, type);
        return redisTemplate.opsForValue().get(captchaRedisKey);
    }

}