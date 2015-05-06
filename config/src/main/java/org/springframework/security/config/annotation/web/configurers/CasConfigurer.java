/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web.configurers;

import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * Adds support for CAS authentication.
 *
 * @author Anderson Davi
 * @since 4.0.1
 */
public class CasConfigurer<H extends HttpSecurityBuilder<H>> extends
        AbstractHttpConfigurer<CasConfigurer<H>, H> {

        private AuthenticationUserDetailsService<CasAssertionAuthenticationToken> authenticationUserDetailsService;

        private TicketValidator ticketValidator;

        private String key;

        private String casServerEndpoint;

        /**
         * Creates a new instance
         */
        public CasConfigurer() {}

        @Override
        public void init(H http) throws Exception {
                super.init(http);

                CasAuthenticationProvider authenticationProvider = new CasAuthenticationProvider();
                authenticationProvider.setAuthenticationUserDetailsService(authenticationUserDetailsService);
                authenticationProvider.setTicketValidator(ticketValidator);
                authenticationProvider.setKey(key);
                authenticationProvider = postProcess(authenticationProvider);
                http.authenticationProvider(authenticationProvider);
                http.setSharedObject(AuthenticationEntryPoint.class, new CasAuthenticationEntryPoint());
        }

        @Override
        public void configure(H http) throws Exception {
                //AuthenticationManager am = http.getSharedObject(AuthenticationManager.class);
                //getAuthenticationFilter().setAuthenticationManager(am);
                http.addFilter(new CasAuthenticationFilter());
                super.configure(http);
        }

        public CasConfigurer<H> authenticationUserDetailsService(
                AuthenticationUserDetailsService<CasAssertionAuthenticationToken> authenticationUserDetailsService) {
                this.authenticationUserDetailsService = authenticationUserDetailsService;
                return this;
        }

        public CasConfigurer<H> casServerEndpoint(String casServerEndpoint) {
                this.casServerEndpoint = casServerEndpoint;
                return this;
        }

        public CasConfigurer<H> ticketValidator(TicketValidator ticketValidator) {
                this.ticketValidator = ticketValidator;
                return this;
        }

        public CasConfigurer<H> key(String key) {
                this.key = key;
                return this;
        }
}
