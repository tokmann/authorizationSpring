package SecurityApplication.service;

import SecurityApplication.DTO.*;
import SecurityApplication.Exceptions.AuthenticationException;
import SecurityApplication.Exceptions.RegistrationException;
import SecurityApplication.model.User;
import SecurityApplication.repository.UserRepository;
import SecurityApplication.utils.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final AuthenticationManager authenticationManager;
    private final CustomUserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    public AuthService(AuthenticationManager authenticationManager,
                       CustomUserDetailsService userDetailsService,
                       PasswordEncoder passwordEncoder,
                       UserRepository userRepository,
                       JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
        this.jwtUtil = jwtUtil;
    }

    public LoginResponse login(LoginRequest request) {

        log.info("Login request received: " + request.toString());

        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(),
                request.getPassword()));

        UserDetails userDetails = userDetailsService.loadUserByUsername(request.getUsername());

        String token = jwtUtil.generateToken(userDetails);

        return new LoginResponse(token, jwtUtil.extractExpiration(token), request.getUsername());
    }

    public UserResponse register(RegisterRequest request) {

        log.info("Register request received: " + request.toString());

        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new RegistrationException("Username is already in use");
        }

        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        userRepository.save(user);

        log.info("User registered: " + user);

        return new UserResponse(user.getId().toString(), user.getUsername());
    }

    public AuthResponse auth(String token) {

        log.info("Auth request received: " + token);

        try {
            if (token.startsWith("Bearer ")) {
                token = token.substring(7);
            }

            String username = jwtUtil.extractUsername(token);

            log.info("Extracted username: " + username);

            UserDetails userDetails = userDetailsService.loadUserByUsername(username);

            if (!jwtUtil.validateToken(token, userDetails)) {
                throw new AuthenticationException("Invalid token");
            }

            log.info("Token validated");

            User user = (User) userDetails;

            return new AuthResponse(true, jwtUtil.extractExpiration(token), username, user.getId());

        } catch (ClassCastException e) {
            log.error("UserDetails is not of type User", e);
            return new AuthResponse(false, null, null, null);
        } catch (Exception e) {
            return new AuthResponse(false, null, null, null);
        }
    }
}
