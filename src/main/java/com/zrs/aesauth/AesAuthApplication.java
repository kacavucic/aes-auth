package com.zrs.aesauth;

import com.zrs.aesauth.config.KeycloakServerProperties;
import lombok.extern.jbosslog.JBossLog;
import org.keycloak.common.Profile;
import org.keycloak.common.Version;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.liquibase.LiquibaseAutoConfiguration;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;

@JBossLog
@SpringBootApplication(exclude = LiquibaseAutoConfiguration.class)
@EnableConfigurationProperties({ KeycloakServerProperties.class })
public class AesAuthApplication {

    private static final Logger LOG = LoggerFactory.getLogger(AesAuthApplication.class);

    public static void main(String[] args) throws Exception {
        SpringApplication.run(AesAuthApplication.class, args);
    }

    @Bean
    ApplicationListener<ApplicationReadyEvent> onApplicationReadyEventListener(ServerProperties serverProperties,
                                                                               KeycloakServerProperties keycloakServerProperties) {

        return (evt) -> {

            Integer port = serverProperties.getPort();
            String keycloakContextPath = keycloakServerProperties.getContextPath();

            log.infof("Using Keycloak Version: %s", Version.VERSION_KEYCLOAK);
            log.infof("Enabled Keycloak Features (Deprecated): %s", Profile.getDeprecatedFeatures());
            log.infof("Enabled Keycloak Features (Preview): %s", Profile.getPreviewFeatures());
            log.infof("Enabled Keycloak Features (Experimental): %s", Profile.getExperimentalFeatures());
            log.infof("Enabled Keycloak Features (Disabled): %s", Profile.getDisabledFeatures());


            LOG.info("Embedded Keycloak started: http://localhost:{}{} to use keycloak", port, keycloakContextPath);
        };
    }

}
