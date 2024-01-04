package com.vains.authorization.property;

import lombok.Data;

import java.util.List;

@Data
public class ValidateInfo {

    /**
     * 获取验证码缓存key的请求头
     */
    private String cacheKey;

    /**
     * 获取验证码的参数名
     */
    private String codeParameter;

    /**
     * 请求信息
     */
    private List<MatcherInfo> matcherInfos;

    /**
     * 请求路径，默认请求方式为Http POST
     */
    private List<String> requestUris;

}