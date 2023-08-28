package com.JWT.jwtSecurity.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// we can use any of these annotations : service, component, repository
@Component
//@RequiredArgsConstructor // lombok creates a constructor for all our final elements
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService; // a service that extracts username for jwt token
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request, // this is the request
            @NonNull HttpServletResponse response, // this is the response
            @NonNull FilterChain filterChain) // chain of responsibility design patter
            throws ServletException, IOException {

        // check if jwt token exist
                final String authHeader = request.getHeader("Authorization"); // extract authentication Header from request Header
                final String jwt;
                final String userEmail;
                if(authHeader == null || !authHeader.startsWith("Bearer ")){
                    filterChain.doFilter(request, response);
                    return;
                }

                // extract jwt token from authorization header
                jwt = authHeader.substring(7); // we want to ignore the "Bearer "

                // now calls the JWT service to extract the username
                //extract userEamil from jwt Token
                userEmail = jwtService.extractUsername(jwt);

                // VALIDATE JWT PROCESS
                // WE VALIDATE ONLY IF WE HAVE USERNAME AND THE USER IS NOT ALREADY AUTHENTICATED
                if(userEmail != null || SecurityContextHolder.getContext().getAuthentication() == null){
                   // get user details from database
                    UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
                    // check if token is valid or not
                    if(jwtService.isTokenValid(jwt, userDetails)){
                        // update the security context
                        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null, // here since we don't have any credentials we pass null for credentials
                                userDetails.getAuthorities()
                        );
                        authToken.setDetails(
                                new WebAuthenticationDetailsSource().buildDetails(request)
                        );
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                    }
                }
            filterChain.doFilter(request, response);
    }
}
