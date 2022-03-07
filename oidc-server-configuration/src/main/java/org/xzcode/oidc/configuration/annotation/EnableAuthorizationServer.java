package org.xzcode.oidc.configuration.annotation;

import org.springframework.context.annotation.Import;
import org.xzcode.oidc.configuration.AuthorizationServerConfiguration;
import org.xzcode.oidc.configuration.AuthorizationServerSecurityConfiguration;
import org.xzcode.oidc.configuration.ResourceServerSecurityConfiguration;

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
