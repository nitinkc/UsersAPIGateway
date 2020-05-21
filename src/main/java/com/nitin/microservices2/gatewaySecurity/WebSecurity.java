package com.nitin.microservices2.gatewaySecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.AuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {

	@Autowired
	private Environment env;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		http.csrf().disable();
		http.headers().frameOptions().disable();
		
		http.authorizeRequests()
		.antMatchers(env.getProperty("api.h2console.url")).permitAll()
		.antMatchers(HttpMethod.GET,env.getProperty("api.users.health.check")).permitAll()
		.antMatchers(HttpMethod.GET,"users-ws/users/").permitAll()
		//Allow Registration
		.antMatchers(HttpMethod.POST,env.getProperty("api.users.registration.url")).permitAll()
		//Allow Login
		.antMatchers(HttpMethod.POST,env.getProperty("api.users.login.url")).permitAll()
		//Making the API Stateless; most strict. Never creates http session
		.anyRequest().authenticated()
		.and()
		.addFilter(new AuthFilter(authenticationManager(),env));
	
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	}
	
}
