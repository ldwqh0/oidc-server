package org.xzcode.oidc.client;

import org.xzcode.oidc.exception.NoSuchClientException;

public interface ClientDetailsService {
    ClientDetails loadClientByClientId(String clientId) throws NoSuchClientException;
}
