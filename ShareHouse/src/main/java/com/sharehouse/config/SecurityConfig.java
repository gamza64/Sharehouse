package com.sharehouse.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig{

	@Autowired
	private BoardUserDetailsService boardUserDetailsService;
		


	
	@Bean
	public SecurityFilterChain filterChain(HttpSecurity security) throws Exception {
	
		
		
		security.authorizeRequests().antMatchers("/","/admin/ad_query_view/**").permitAll(); 
		security.authorizeRequests().antMatchers("/member/**","/registration/**","/mypage/**").authenticated(); //비로그인시 uri에 대해 권한이 없으면 로그인창으로 이동
		security.authorizeRequests().antMatchers("/admin/**").hasAnyRole("ADMIN"); //역할에 대한 허가
   
		security.csrf().disable(); //post매핑에 대한 씨큐리티 비활성화
		security.formLogin().loginPage("/login").defaultSuccessUrl("/", true); //로그인시 '/login'으로 이동, 로그인 성공시 "/"로 이동
		security.exceptionHandling().accessDeniedPage("/accessDenied"); //로그인시 uri에 대해 권한이 없으면 "/accessDenied"로 이동 //에러페이지 예방
		security.logout().invalidateHttpSession(true).logoutSuccessUrl("/login"); //로그아웃 성공 시 로그인 페이지로 이동
		security.headers().frameOptions().sameOrigin(); 
		security.userDetailsService(boardUserDetailsService); // 주입받은 객체 넘겨줌 //db정보와 비교하면서 처리->로그인되면 로그인 페이지로 이동시켜줌
		return security.build(); //설정해놓은 코드 실행

		
	
	}
	
	// 비밀번호 암호화 처리
	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}
	
	@Autowired
	public void authenticate(AuthenticationManagerBuilder auth) throws Exception{
		auth.inMemoryAuthentication()
		.withUser("manager")
		.password("{noop}manager123")
		.roles("MANAGER");
		
		auth.inMemoryAuthentication()
		.withUser("admin")
		.password("{noop}admin123")
		.roles("ADMIN","MANAGER");
		
	}
	
	

}