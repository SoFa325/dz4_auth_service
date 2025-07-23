package org.example.dz4_auth_service.service;

import org.example.dz4_auth_service.DTO.User;
import org.example.dz4_auth_service.DTO.UserDetailsImpl;
import org.example.dz4_auth_service.jwt.AuthEntryPointJWT;
import org.example.dz4_auth_service.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    private static final Logger logger = LoggerFactory.getLogger(AuthEntryPointJWT.class);

    private final UserRepository userRepository;

    public UserDetailsServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        logger.debug("Loading user: {}", username);  // Добавьте это
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> {
                    logger.error("User not found: {}", username);  // Важно!
                    return new UsernameNotFoundException("User not found");
                });
        return UserDetailsImpl.build(user);
    }
}