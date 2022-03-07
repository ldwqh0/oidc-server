package org.xzcode.oidc.server.security.web.authentication.www;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.xzcode.oidc.client.ClientDetails;
import org.xzcode.oidc.client.ClientDetailsService;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames.CLIENT_ID;

/**
 * 一个简单的public type client Authentication Filter，他的目就是获取类型为public的client的认证授权信息，并且通过验证
 */
public class PublicClientAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(PublicClientAuthenticationFilter.class);

    private final ClientDetailsService clientDetailsService;

    public PublicClientAuthenticationFilter(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (requiresAuthentication(request)) {
            try {
                String clientId = request.getParameter("client_id");
                Authentication result = authentication(clientId);
                SecurityContextHolder.getContext().setAuthentication(result);
            } catch (AuthenticationException ex) {
                SecurityContextHolder.clearContext();
            }
        }
        filterChain.doFilter(request, response);
    }


    private boolean requiresAuthentication(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        String clientId = request.getParameter(CLIENT_ID);
        return StringUtils.isBlank(header) && StringUtils.isNotBlank(clientId) && authenticationIsRequired();
    }

    private boolean authenticationIsRequired() {
        // Only reauthenticate if username doesn't match SecurityContextHolder and user
        // isn't authenticated (see SEC-53)
        Authentication existingAuth = SecurityContextHolder.getContext().getAuthentication();
        return existingAuth == null || !existingAuth.isAuthenticated();
    }

    private Authentication authentication(String clientId) {
        ClientDetails client = this.clientDetailsService.loadClientByClientId(clientId);
        if (ClientDetails.ClientType.CLIENT_PUBLIC.equals(client.getType())) {
            return new UsernamePasswordAuthenticationToken(client, null, client.getAuthorities());
        } else {
            log.debug("no public client {} try to authentication with public ,ignored", clientId);
            return null;
        }
    }
}
