package uk.gov.homeoffice.borders.workflow.security;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.camunda.bpm.engine.IdentityService;
import org.camunda.bpm.engine.impl.identity.Authentication;
import org.keycloak.adapters.RefreshableKeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.account.SimpleKeycloakAccount;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;

import java.util.ArrayList;

@Slf4j
@AllArgsConstructor(onConstructor = @__(@Autowired))
public class SecurityEventListener {

    private IdentityService identityService;

    @EventListener
    public void onSuccessfulAuthentication(InteractiveAuthenticationSuccessEvent successEvent) {
        KeycloakAuthenticationToken keycloakAuthenticationToken = (KeycloakAuthenticationToken) successEvent.getSource();
        RefreshableKeycloakSecurityContext keycloakSecurityContext = ((SimpleKeycloakAccount)
                keycloakAuthenticationToken.getDetails()).getKeycloakSecurityContext();

        String userId = keycloakSecurityContext.getToken().getEmail();
        log.debug("User id '{}' authenticated", userId);
        identityService.setAuthentication(new Authentication(userId, new ArrayList<>()));
    }
}
