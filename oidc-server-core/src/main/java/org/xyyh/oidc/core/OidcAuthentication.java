package org.xyyh.oidc.core;

import org.apache.commons.lang3.NotImplementedException;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.xyyh.oidc.client.ClientDetails;
import org.xyyh.oidc.endpoint.request.OpenidAuthorizationRequest;
import org.xyyh.oidc.userdetails.OidcUserDetails;

import javax.validation.constraints.NotNull;
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
    @NotNull ClientDetails getClient();

    // todo 这个是不是为空有待考证
    @Nullable
    OidcUserDetails getUser();

    /**
     * the authorized scopes
     */
    Set<String> getScopes();

    /**
     * the {@link  OpenidAuthorizationRequest}
     *
     * @see OpenidAuthorizationRequest
     */
    OpenidAuthorizationRequest getRequest();

    static OidcAuthentication of(ApprovalResult approvalResult, ClientDetails client, OidcUserDetails user) {
        return new DefaultOidcAuthenticationToken(null, approvalResult, client, user);
    }


    static OidcAuthentication of(OpenidAuthorizationRequest request,
                                 ApprovalResult result,
                                 ClientDetails client,
                                 OidcUserDetails user) {
        return new DefaultOidcAuthenticationToken(request, result, client, user);
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

    private final OidcUserDetails user;

    private final OpenidAuthorizationRequest request;

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
    public DefaultOidcAuthenticationToken(OpenidAuthorizationRequest request,
                                          ApprovalResult result,
                                          @NotNull ClientDetails client,
                                          OidcUserDetails user) {
        this.client = client;
        this.approvalResult = result;
        this.user = user;
        this.request = request;
    }

    public ApprovalResult getApprovalResult() {
        return approvalResult;
    }

    @Override
    public OidcUserDetails getUser() {
        return user;
    }

    @Override
    public Object getCredentials() {
        return "NaN";
    }

    @Override
    public Object getPrincipal() {
        return Objects.isNull(this.user) ? this.client : this.user;
    }

    @Override
    public String getName() {
        return Objects.isNull(this.user) ? this.request.getClientId()
            : this.user.getUsername();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Objects.isNull(this.user) ? null : this.user.getAuthorities();
    }

    @Override
    public Object getDetails() {
        // TODO 这个有待进一步处理 details不仅应该包含user,还要包含client
        return null;
//        return Objects.isNull(this.user) ? this.approvalResult : this.user.getDetails();
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
    public OpenidAuthorizationRequest getRequest() {
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
