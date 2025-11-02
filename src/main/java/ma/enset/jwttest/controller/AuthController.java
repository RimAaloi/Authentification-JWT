package ma.enset.jwttest.controller;

import ma.enset.jwttest.record.AuthRequest;
import ma.enset.jwttest.record.AuthResponse;
import ma.enset.jwttest.service.JwtService;
import ma.enset.jwttest.service.MyUserDetailsService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api")
public class AuthController {

    private final JwtService jwtService;
    private final MyUserDetailsService myUserDetailsService;
    private final AuthenticationManager authenticationManager;

    // Injection via AuthenticationConfiguration
    public AuthController(JwtService jwtService,
                          MyUserDetailsService myUserDetailsService,
                          AuthenticationConfiguration authenticationConfiguration) throws Exception {
        this.jwtService = jwtService;
        this.myUserDetailsService = myUserDetailsService;
        this.authenticationManager = authenticationConfiguration.getAuthenticationManager();
    }

    @PostMapping("/auth/login")
    public ResponseEntity<AuthResponse> login(@RequestBody AuthRequest req) {
            // Authentifier l'utilisateur
            var authToken = new UsernamePasswordAuthenticationToken(req.userName(), req.password());
            authenticationManager.authenticate(authToken);

            // Charger les détails de l'utilisateur
            UserDetails user = myUserDetailsService.loadUserByUsername(req.userName());

            // Générer le token JWT
            String token = jwtService.generateToken(
                    user.getUsername(),
                    Map.of("roles", user.getAuthorities())
            );

            return ResponseEntity.ok(new AuthResponse(token, "Connexion réussie"));


    }

    @GetMapping("/health")
    public Map<String, String> healthCheck() {
        return Map.of("msg1","🚀 Serveur démarré avec succès!");
    }

    @GetMapping("/version")
    public Map<String, String> getVersion() {
        return Map.of("msg2","Version 1.0.0 - API Spring Boot");
    }
}