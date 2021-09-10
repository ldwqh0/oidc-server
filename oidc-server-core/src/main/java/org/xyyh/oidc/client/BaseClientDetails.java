package org.xyyh.oidc.client;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.util.Collection;
import java.util.Collections;
import java.util.Set;

import static org.xyyh.oidc.collect.Sets.hashSet;
import static org.xyyh.oidc.collect.Sets.transform;

public class BaseClientDetails implements ClientDetails {

    private static final long serialVersionUID = -7386163121370242465L;

    private final String clientId;
    private final String clientSecret;
    private final boolean autoApproval;
    private final Set<String> scopes;
    private final Set<String> registeredRedirectUris;
    private final Set<AuthorizationGrantType> authorizedGrantTypes;

    private final Integer accessTokenValiditySeconds;

    private final Integer refreshTokenValiditySeconds;
    private final boolean accountExpired;
    private final boolean accountLocked;
    private final boolean credentialsExpired;
    private final boolean enabled;
    private final Collection<? extends GrantedAuthority> authorities;

    private final ClientType type;

    public BaseClientDetails(
        String clientId,
        String clientSecret,
        ClientType type,
        boolean autoApproval,
        Set<String> scope,
        Set<String> registeredRedirectUris,
        Set<String> authorizedGrantTypes,
        Collection<? extends GrantedAuthority> authorities,
        Integer accessTokenValiditySeconds,
        Integer refreshTokenValiditySeconds,
        boolean accountExpired,
        boolean accountLocked,
        boolean credentialsExpired,
        boolean enabled) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.autoApproval = autoApproval;
        this.scopes = hashSet(scope);
        this.registeredRedirectUris = hashSet(registeredRedirectUris);
        this.authorizedGrantTypes = transform(authorizedGrantTypes, AuthorizationGrantType::new);
        this.authorities = Collections.unmodifiableCollection(authorities);
        this.accessTokenValiditySeconds = accessTokenValiditySeconds;
        this.refreshTokenValiditySeconds = refreshTokenValiditySeconds;
        this.type = type;
        this.accountExpired = accountExpired;
        this.accountLocked = accountLocked;
        this.credentialsExpired = credentialsExpired;
        this.enabled = enabled;
    }

    @Override
    public Integer getAccessTokenValiditySeconds() {
        return accessTokenValiditySeconds;
    }

    @Override
    public Integer getRefreshTokenValiditySeconds() {
        return refreshTokenValiditySeconds;
    }

    @Override
    public String getClientId() {
        return this.clientId;
    }

    @Override
    public String getClientSecret() {
        return this.clientSecret;
    }

    @Override
    public Set<String> getScopes() {
        return this.scopes;
    }

    @Override
    public Set<String> getRegisteredRedirectUris() {
        return registeredRedirectUris;
    }

    @Override
    public boolean isAutoApproval() {
        return autoApproval;
    }

    @Override
    public ClientType getType() {
        return this.type;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((clientId == null) ? 0 : clientId.hashCode());
        result = prime * result + ((clientSecret == null) ? 0 : clientSecret.hashCode());
        result = prime * result + ((scopes == null) ? 0 : scopes.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        BaseClientDetails other = (BaseClientDetails) obj;
        if (clientId == null) {
            if (other.clientId != null)
                return false;
        } else if (!clientId.equals(other.clientId))
            return false;
        if (clientSecret == null) {
            if (other.clientSecret != null)
                return false;
        } else if (!clientSecret.equals(other.clientSecret))
            return false;
        if (scopes == null) {
            return other.scopes == null;
        } else {
            return scopes.equals(other.scopes);
        }
    }

    @Override
    public String toString() {
        return "BaseClientDetails [clientId=" + clientId + ", clientSecret=" + clientSecret + ", scopes=" + scopes
            + ", registeredRedirectUris=" + registeredRedirectUris + ", authorizedGrantTypes="
            + authorizedGrantTypes + "]";
    }

    @Override
    public Set<AuthorizationGrantType> getAuthorizedGrantTypes() {
        return this.authorizedGrantTypes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return this.clientSecret;
    }

    @Override
    public String getUsername() {
        return this.clientId;
    }

    @Override
    public boolean isAccountNonExpired() {
        return !this.accountExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !this.accountLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return !this.credentialsExpired;
    }

    @Override
    public boolean isEnabled() {
        return this.enabled;
    }
}
