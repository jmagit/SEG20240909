package com.example;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
        	.authorizationEndpoint(config -> config.authorizationResponseHandler((req, res, auth) -> { //actions when authentication succeeds
                res.resetBuffer();
                res.setStatus(HttpStatus.OK.value());
                res.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);

                // fetch saved url (visited before being redirected to login page) and return it in response body.
                var savedReq = new HttpSessionRequestCache().getRequest(req, res);
                res.getWriter()
                    .append("{\"redirectUrl\": \"")
                    .append(savedReq == null ? "" : savedReq.getRedirectUrl())
                    .append("\"}");
                res.flushBuffer();
            }))
            .oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
        http
            .cors(Customizer.withDefaults())
			.exceptionHandling((exceptions) -> exceptions
					.defaultAuthenticationEntryPointFor(
						new LoginUrlAuthenticationEntryPoint("/login"),
						new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
					)
				)
			// Accept access tokens for User Info and/or Client Registration
			.oauth2ResourceServer((resourceServer) -> resourceServer
				.jwt(Customizer.withDefaults()));

        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain authenticationSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/login", "/logout") //limit filter chain to those endpoints only
            .cors(Customizer.withDefaults()) //apply default cors policy
            .csrf((csrf) -> csrf.disable()) //disable csrf to just keep it simple, not safe for prod though
            .formLogin(form -> form
                .loginPage("http://localhost:9090/login") //url to login page
                .loginProcessingUrl("/login") //endpoint where POST login requests will be sent
                .successHandler((req, res, auth) -> { //actions when authentication succeeds
                    res.resetBuffer();
                    res.setStatus(HttpStatus.OK.value());
                    res.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);

                    // fetch saved url (visited before being redirected to login page) and return it in response body.
                    var savedReq = new HttpSessionRequestCache().getRequest(req, res);
                    res.getWriter()
                        .append("{\"redirectUrl\": \"")
                        .append(savedReq == null ? "" : savedReq.getRedirectUrl())
                        .append("\"}");
                    res.flushBuffer();
                })
                .failureHandler( //and when it fails
                    (req, res, ex) -> res.setStatus(HttpStatus.UNAUTHORIZED.value())
                )
            )
            .logout(logout -> logout
                .logoutSuccessUrl("http://localhost:9090/login?logout") //target page after logout
            )
            // actions when any exception arises
            .exceptionHandling(handler -> handler
                .authenticationEntryPoint(
                    new HttpStatusEntryPoint(HttpStatus.FORBIDDEN)
                )
            )
            // secure other potential endpoints
            .authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated()
            );

        return http.build();
    }
    
    @Bean
    @Order(3)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(Customizer.withDefaults())
            .authorizeHttpRequests((authorize) -> authorize
//            	.requestMatchers("/oauth2/authorization/**").permitAll()
                .anyRequest().authenticated()
            );

        return http.build();
    }

    @Bean
    RegisteredClientRepository registeredClientRepository() {
        RegisteredClient publicClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("webapp")
            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost:9090/auth")
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .clientSettings(ClientSettings.builder()
                .requireAuthorizationConsent(false)
                .requireProofKey(true)
                .build()
            )
            .build();

        return new InMemoryRegisteredClientRepository(publicClient);
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        config.addAllowedOrigin("http://localhost:9090");
        config.setAllowCredentials(true);
        source.registerCorsConfiguration("/**", config);
        return source;
    }

	@Bean 
	public UserDetailsService userDetailsService() {
		return new InMemoryUserDetailsManager(
				User.withUsername("user1").password("{noop}1").roles("USER").build(),
				User.withUsername("adm@example.com").password("{noop}P@$$w0rd").roles("USUARIOS", "ADMINISTRADORES").build(),
				User.withUsername("emp@example.com").password("{noop}P@$$w0rd").roles("USUARIOS", "EMPLEADOS").build(),
				User.withUsername("usr@example.com").password("{noop}P@$$w0rd").roles("USUARIOS").build()
			);
	}

}
