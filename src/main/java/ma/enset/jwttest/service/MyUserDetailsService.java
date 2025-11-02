package ma.enset.jwttest.service;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {

    private final InMemoryUserDetailsManager inMemoryUserDetailsManager;

    public MyUserDetailsService() {
        // Création des utilisateurs en mémoire
        UserDetails user = User.withUsername("user")
                .password("{noop}password") // Même mot de passe que votre requête
                .roles("USER")
                .build();

        UserDetails admin = User.withUsername("admin")
                .password("{noop}admin123")
                .roles("ADMIN")
                .build();

        this.inMemoryUserDetailsManager = new InMemoryUserDetailsManager(user, admin);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // ⚠️ CORRECTION : Appeler le delegate au lieu de retourner null
        return inMemoryUserDetailsManager.loadUserByUsername(username);
    }
}