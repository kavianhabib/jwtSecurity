package com.JWT.jwtSecurity.auth;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
public class AuthenticationResponse {
    private String token;

    public AuthenticationResponse(String token) {
        this.token = token;
    }

    public static AuthenticationReponseBuilder builder(){
        return new AuthenticationReponseBuilder();
    }

    public static class AuthenticationReponseBuilder{
        private String token;

        public AuthenticationReponseBuilder(){
        }
        public AuthenticationReponseBuilder setToken(String token){
            this.token = token;
            return this;
        }
        public AuthenticationResponse build(){
            return new AuthenticationResponse(this.token);
        }

    }
}
