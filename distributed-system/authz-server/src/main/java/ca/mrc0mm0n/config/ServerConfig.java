package ca.mrc0mm0n.config;

import static org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.CLIENT_CREDENTIALS;
import static org.springframework.security.oauth2.core.AuthorizationGrantType.REFRESH_TOKEN;
import static org.springframework.security.oauth2.core.ClientAuthenticationMethod.CLIENT_SECRET_BASIC;

import java.util.Set;
import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
@EnableWebSecurity
public class ServerConfig {

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());
		http.exceptionHandling(
				exceptions -> exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
				.oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()));
		return http.build();
	}

	@Bean
	@Order(2)
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
				.formLogin(Customizer.withDefaults());
		return http.build();
	}

	@Bean
	RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
		return new JdbcRegisteredClientRepository(jdbcTemplate);
	}

	@Bean
	JdbcUserDetailsManager jdbcUserDetailsManager(DataSource dataSource) {
		return new JdbcUserDetailsManager(dataSource);
	}

	@Bean
	ApplicationRunner runner(RegisteredClientRepository registeredClientRepository,
			UserDetailsManager userDetailsManager) {
		return args -> {

			// @formatter:off
			if (registeredClientRepository.findByClientId("spring-client") == null) {
				registeredClientRepository.save(
					RegisteredClient.withId(UUID.randomUUID().toString())
						.clientId("spring-client").clientSecret("{noop}secret").clientName("Spring Client")
						.clientAuthenticationMethods(cam -> cam.add(CLIENT_SECRET_BASIC))
						.authorizationGrantTypes(authorizationGrantTypes -> authorizationGrantTypes
								.addAll(Set.of(CLIENT_CREDENTIALS, AUTHORIZATION_CODE, REFRESH_TOKEN)))
						.redirectUris(uri -> {
							uri.add("http://127.0.0.1:8080/login/oauth2/code/spring-client-oidc");
							uri.add("http://127.0.0.1:8080/authorized");
						}).scopes(scopes -> scopes.addAll(Set.of("api1.read", "api1.write", "openid")))
						// .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
						.build()
				);
			}
			// @formatter:on

			if (!userDetailsManager.userExists("user1")) {
				var userBuilder = User.builder();
				UserDetails user1 = userBuilder.username("user1").password("{noop}pass").roles("USER", "ADMIN").build();
				userDetailsManager.createUser(user1);
			}

		};
	}

	@Bean
	public AuthorizationServerSettings providerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

}