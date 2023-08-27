package com.JWT.jwtSecurity.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long>{

    // get user by email : we are using email as username
    Optional<User>  findByEmail(String email);
}
