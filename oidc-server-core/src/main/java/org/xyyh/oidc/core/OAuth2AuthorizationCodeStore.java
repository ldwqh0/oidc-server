package org.xyyh.oidc.core;

import java.util.Optional;

/**
 * 用于存储和消费Authorization Code
 */
public interface OAuth2AuthorizationCodeStore {

    /**
     * 保存一个code和一个授权的关系
     *
     * @param code           要保存的授权码信息
     * @param authentication 权限信息
     * @return 包存的授权信息
     */
    OAuth2AuthorizationCode save(OAuth2AuthorizationCode code, OidcAuthentication authentication);


    /**
     * 消费指定授权码,返回授权信息
     *
     * @param code 授权码
     */
    Optional<OidcAuthentication> consume(String code);

}
