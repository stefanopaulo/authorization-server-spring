package com.algamoney.awm.auth.security;

import java.util.Arrays;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
	
	private final PasswordEncoder passwordEncoder;
	private final AuthenticationManager authenticationManager;
	private final UserDetailsService userDetailsService;
	private final RedisConnectionFactory redisConnectionFactory;

	public AuthorizationServerConfig(PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, UserDetailsService userDetailsService, RedisConnectionFactory redisConnectionFactory) {
		this.passwordEncoder = passwordEncoder;
		this.authenticationManager = authenticationManager;
		this.userDetailsService = userDetailsService;
		this.redisConnectionFactory = redisConnectionFactory;
	}
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients
			.inMemory()
				.withClient("angular")
					.secret(passwordEncoder.encode("@ngul@r0"))
					.authorizedGrantTypes("password", "refresh_token")
					.scopes("write", "read")
					.accessTokenValiditySeconds(6 * 60 * 60)
					.refreshTokenValiditySeconds(3600 * 24)
			.and()
				.withClient("mobile")
					.secret("m0b1l3#")
					.authorizedGrantTypes("password", "refresh_token")
					.scopes("write", "read")
					.accessTokenValiditySeconds(6 * 60 * 60)
					.refreshTokenValiditySeconds(3600 * 24)
			.and()
				.withClient("moneyanalitics")
					.secret(passwordEncoder.encode(""))
					.authorizedGrantTypes("authorization_code")
					.scopes("write", "read")
					.redirectUris("http://client-application")
					.accessTokenValiditySeconds(6 * 60 * 60)
					.refreshTokenValiditySeconds(3600 * 24)
			.and()
				.withClient("faturamento")
					.secret(passwordEncoder.encode("faturamento123"))
					.authorizedGrantTypes("client_credentials")
					.scopes("read")
			.and()
				.withClient("checktoken")
					.secret(passwordEncoder.encode("check123"));
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
			.authenticationManager(authenticationManager)
			.userDetailsService(userDetailsService)
			.reuseRefreshTokens(false)
			.accessTokenConverter(jwtAccessTokenConverter())
			.tokenGranter(tokenGranter(endpoints));
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security.checkTokenAccess("permitAll()")
				.allowFormAuthenticationForClients();
	}
	
	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
		
		jwtAccessTokenConverter.setSigningKey("algamoney");
		
		return jwtAccessTokenConverter;
	}
	
	private TokenGranter tokenGranter(AuthorizationServerEndpointsConfigurer endpoints) {
		PkceAuthorizationCodeTokenGranter pkceAuthorizationCodeTokenGranter = new PkceAuthorizationCodeTokenGranter(endpoints.getTokenServices(),
				endpoints.getAuthorizationCodeServices(), endpoints.getClientDetailsService(),
				endpoints.getOAuth2RequestFactory());
		
		List<TokenGranter> granters = Arrays.asList(
				pkceAuthorizationCodeTokenGranter, endpoints.getTokenGranter());
		
		return new CompositeTokenGranter(granters);
	}

}
