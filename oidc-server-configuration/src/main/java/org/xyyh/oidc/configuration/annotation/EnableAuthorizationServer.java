package org.xyyh.oidc.configuration.annotation;

import org.springframework.context.annotation.Import;
import org.xyyh.oidc.configuration.AuthorizationServerConfiguration;
import org.xyyh.oidc.configuration.AuthorizationServerSecurityConfiguration;
import org.xyyh.oidc.configuration.ResourceServerSecurityConfiguration;

import java.lang.annotation.*;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import({
    AuthorizationServerConfiguration.class,
    ResourceServerSecurityConfiguration.class,
    AuthorizationServerSecurityConfiguration.class,
})
public @interface EnableAuthorizationServer {

}
