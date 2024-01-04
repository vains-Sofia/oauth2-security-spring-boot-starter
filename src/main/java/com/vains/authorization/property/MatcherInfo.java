package com.vains.authorization.property;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpMethod;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class MatcherInfo {

    /**
     * 请求路径
     */
    private String url;

    /**
     * Http请求方式，{@link HttpMethod}
     */
    private String httpMethod = HttpMethod.POST.name();

    public MatcherInfo(String url) {
        this.url = url;
    }

}