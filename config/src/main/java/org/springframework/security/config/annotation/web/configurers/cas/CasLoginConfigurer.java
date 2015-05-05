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
package org.springframework.security.config.annotation.web.configurers.cas;

import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Adds support for CAS authentication.
 *
 * @author Anderson Davi
 * @since 4.0.1
 */
public class CasLoginConfigurer<H extends HttpSecurityBuilder<H>> extends
        AbstractAuthenticationFilterConfigurer<H, CasLoginConfigurer<H>, CasAuthenticationFilter> {

        /**
         * Creates a new instance
         */
        public CasLoginConfigurer() {
                super(new CasAuthenticationFilter(), "/login/cas");
        }

        /*
        * (non-Javadoc)
        *
        * @see org.springframework.security.config.annotation.web.configurers.
        * AbstractAuthenticationFilterConfigurer
        * #createLoginProcessingUrlMatcher(java.lang.String)
        */
        @Override
        protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
                return new AntPathRequestMatcher(loginProcessingUrl);
        }
}
