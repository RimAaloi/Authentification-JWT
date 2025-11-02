package ma.enset.jwttest.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {

    private final InMemoryUserDetailsManager delegate;

    public MyUserDetailsService() {
        UserDetails user =User.withUsername("user")
                .password("{noop}user123") // {noop} = pas d'encodage pour les tests
                .roles("USER")
                .build();
        UserDetails admin =User.withUsername("admin")
                .password("{noop}admin123")
                .roles("ADMIN")
                .build();

        this.delegate = new InMemoryUserDetailsManager(user,admin);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return null;
    }

}