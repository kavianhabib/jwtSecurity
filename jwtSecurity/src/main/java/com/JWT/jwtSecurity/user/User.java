package com.JWT.jwtSecurity.user;

import jakarta.persistence.*;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data// this is from lombok and gives us getter, setter and tostring
@Builder // allow us to build the object using builder pattern
//@NoArgsConstructor
//@RequiredArgsConstructor
@Entity(name = "User")
@Table(name = "tblUser")
public class User implements UserDetails {
    @Id
    @SequenceGenerator(
            name = "user_sequence",
            sequenceName = "user_sequence",
            allocationSize = 1
    )
    @GeneratedValue(
            strategy = GenerationType.SEQUENCE,
            generator = "user_sequence"
    )
    private Long id;

    @Column(
            name = "first_name",
            nullable = false,
            updatable = false,
            columnDefinition = "TEXT",
            length = 50
    )
    private String firstName;
    @Column(
            name = "last_name",
            nullable = false,
            updatable = false,
            columnDefinition = "TEXT",
            length = 50
    )
    private String lastName;

    @Column(
            name = "email",
            nullable = false,
            columnDefinition = "TEXT",
            length = 100
    )
    private String email;

    @Column(
            name = "password",
            nullable = false,
            columnDefinition = "TEXT",
            length = 100
    )
    private String password;


    @Enumerated(
            EnumType.STRING
    )
    private Role role;

    @Column(
            name = "is_account_locked",
            nullable = false
    )
    public boolean isAccountLocked;

    @Column(
            name = "is_credential_expired",
            nullable = false
    )
    public boolean isCredentialExpired;

    @Column(
            name = "is_account_expired",
            nullable = false
    )
    public boolean isAccountExpired;

    @Column(
            name = "is_enabled",
            nullable = false
    )
    public boolean isEnabled;

    public User(String firstName, String lastName, String email, String password, Role role) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
        this.password = password;
        this.role = role;
    }
    public User(){

    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    @Override
    public String getUsername() {
        return this.email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return !this.isAccountExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !this.isAccountLocked ;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return !this.isCredentialExpired;
    }

    @Override
    public boolean isEnabled() {
        return !this.isEnabled;
    }

    @Override
    public String getPassword(){
        return this.password;
    }

//    public User(String firstName, String lastName, String email, String password) {
//        this.firstName = firstName;
//        this.lastName = lastName;
//        this.email = email;
//        this.password = password;
//    }

    public static UserBuilder builder(){
        return new UserBuilder();
    }
    public static class UserBuilder{
        public String firstName;
        public String lastName;
        public String email;
        public String password;
        public Role role;

        public UserBuilder(){

        }
        public UserBuilder setFirstName(String firstName){
            this.firstName = firstName;
            return this;
        }
        public UserBuilder setLastName(String lastName){
            this.lastName = lastName;
            return this;
        }

        public UserBuilder setEmail(String email){
            this.email = email;
            return this;
        }
        public UserBuilder setPassword(String password){
            this.password = password;
            return this;
        }
        public UserBuilder setRole(Role role){
            this.role = role;
            return this;
        }

        public User build(){
            return  new User(
                    this.firstName,
                    this.lastName,
                    this.email,
                    this.password,
                    this.role
            );
        }

    }
}
