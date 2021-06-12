package org.xyyh.oidc.core;

import org.apache.commons.lang3.NotImplementedException;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.xyyh.oidc.client.ClientDetails;
import org.xyyh.oidc.endpoint.request.OidcAuthorizationRequest;

import java.util.Collection;
import java.util.Objects;
import java.util.Set;

/**
 * 一个 oauth2 授权信息，包括授权用户信息，授权 scope 和 client 信息
 */
public interface OidcAuthentication extends Authentication, CredentialsContainer {

    /**
     * the {@link ClientDetails}
     */
    ClientDetails getClient();

    // todo 这个是不是为空有待考证
    @Nullable
    Authentication getUser();

    /**
     * the authorized scopes
     */
    Set<String> getScopes();

    ApprovalResult getApprovalResult();

    /**
     * the {@link  OidcAuthorizationRequest}
     *
     * @see OidcAuthorizationRequest
     */
    OidcAuthorizationRequest getRequest();

    static OidcAuthentication of(ApprovalResult approvalResult, ClientDetails client, Authentication user) {
        return new DefaultOidcAuthenticationToken(null, approvalResult, client, user, null);
    }


    static OidcAuthentication of(OidcAuthorizationRequest request,
                                 ApprovalResult result,
                                 ClientDetails client,
                                 Authentication user) {
        return new DefaultOidcAuthenticationToken(request, result, client, user, null);
    }

    static OidcAuthentication from(OidcAuthentication authentication, Object details) {
        return new DefaultOidcAuthenticationToken(authentication.getRequest(), authentication.getApprovalResult(),
            authentication.getClient(),
            authentication.getUser(),
            details
        );
    }

}

/**
 * 授权结果token
 *
 * @author LiDong
 */
class DefaultOidcAuthenticationToken implements OidcAuthentication {
    private static final long serialVersionUID = -6827330735137748398L;

    private final ClientDetails client;

    private final ApprovalResult approvalResult;

    private final Authentication user;

    private final OidcAuthorizationRequest request;

    private final Object details;

    @Override
    public boolean isAuthenticated() {
        return this.approvalResult.isApproved();
        // todo 这里需要重新思考
        //            && (Objects.isNull(user) || user.isAuthenticated());
    }

    public boolean isClientOnly() {
        return Objects.isNull(user);
    }

    /**
     * 使用指定的信息构建一个 {@link OidcAuthentication}
     *
     * @param request 授权请求
     * @param result  授权结果
     * @param client  client信息
     * @param user    用户信息
     */
    public DefaultOidcAuthenticationToken(OidcAuthorizationRequest request,
                                          ApprovalResult result,
                                          ClientDetails client,
                                          Authentication user,
                                          Object details) {
        this.client = client;
        this.approvalResult = result;
        this.user = user;
        this.request = request;
        this.details = details;
    }

    @Override
    public ApprovalResult getApprovalResult() {
        return approvalResult;
    }

    @Override
    public Authentication getUser() {
        return user;
    }

    @Override
    public Object getCredentials() {
        return "NaN";
    }

    @Override
    public Object getPrincipal() {
        return Objects.isNull(this.user) ? this.client : this.user.getPrincipal();
    }

    @Override
    public String getName() {
        return Objects.isNull(this.user) ? this.request.getClientId() : this.user.getName();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Objects.isNull(this.user) ? null : this.user.getAuthorities();
    }

    @Override
    public Object getDetails() {
        return details;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        throw new NotImplementedException("the method is not implemented");
    }

    @Override
    public ClientDetails getClient() {
        return client;
    }

    @Override
    public Set<String> getScopes() {
        return approvalResult.getScopes();
    }

    @Override
    public OidcAuthorizationRequest getRequest() {
        return this.request;
    }

    @Override
    public void eraseCredentials() {
        if (this.user != null
            && CredentialsContainer.class.isAssignableFrom(this.user.getClass())) {
            ((CredentialsContainer) this.user).eraseCredentials();
        }
    }
}
