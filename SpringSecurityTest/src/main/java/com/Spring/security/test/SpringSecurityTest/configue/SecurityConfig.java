package com.Spring.security.test.SpringSecurityTest.configue;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }




    @Bean
    public UserDetailsService userDetailsService() {
//        UserDetails normalUser = User.withUsername("Arjun")
//                .password(passwordEncoder().encode("Arjun@12345")).roles("NORMAL")
//                .build();
//
//        UserDetails adminUser = User.withUsername("Bhavesh")
//                .password(passwordEncoder().encode("Bhavesh@12345")).roles("ADMIN")
//                .build();
//        InMemoryUserDetailsManager inMemoryUserDetailsManager=new InMemoryUserDetailsManager(normalUser,adminUser);
//    return inMemoryUserDetailsManager;
     return new CustomUserDetailService();
    }



    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf(httpSecurityCsrfConfigurer -> httpSecurityCsrfConfigurer.disable())
                .authorizeRequests()

              //  .requestMatchers("/home/admin")
              //  .hasRole("ADMIN")

              //  .requestMatchers("/home/normal")
              //  .hasRole("NORMAL")

              //  .requestMatchers("/home/public")
               // .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin(formLogin ->
                        formLogin
                                .permitAll());
        return httpSecurity.build();
    }
}
