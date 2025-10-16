    package backend.example.identityservice.entity;

    import backend.example.identityservice.utils.AccountStatus;
    import jakarta.persistence.*;
    import lombok.*;
    import lombok.experimental.FieldDefaults;
    import org.springframework.security.core.GrantedAuthority;
    import org.springframework.security.core.authority.SimpleGrantedAuthority;
    import org.springframework.security.core.userdetails.UserDetails;

    import java.util.Collection;
    import java.util.Set;


    @AllArgsConstructor
    @NoArgsConstructor
    @Getter
    @Setter
    @Builder
    @FieldDefaults(level = AccessLevel.PRIVATE)
    @Entity
    public class User implements UserDetails {
        @Id
        @GeneratedValue(strategy = GenerationType.UUID)
        String id;

        @Column(name = "username", unique = true, columnDefinition = "VARCHAR(255) COLLATE utf8mb4_unicode_ci")
        String username;

        String password;

        @Column(name = "email", unique = true, columnDefinition = "VARCHAR(255) COLLATE utf8mb4_unicode_ci")
        String email;

        @Enumerated(EnumType.STRING)
        @Column(nullable = false)
        @Builder.Default
        private AccountStatus accountStatus = AccountStatus.ACTIVE;

        @ManyToMany(fetch = FetchType.EAGER)
        @JoinTable(
                name = "user_roles",
                joinColumns = @JoinColumn(name = "user_id"),
                inverseJoinColumns = @JoinColumn(name = "role_id")
        )
        Set<Role> roles;

        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return roles.stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role.getName())) // ROLE_USER, ROLE_ADMIN
                    .toList();
        }

        @Override
        public boolean isAccountNonExpired() {
            return true;
        }

        @Override
        public boolean isAccountNonLocked() {
            return this.accountStatus != AccountStatus.LOCKED;
        }

        @Override
        public boolean isCredentialsNonExpired() {
            return true;
        }

        @Override
        public boolean isEnabled() {
            return this.accountStatus == AccountStatus.ACTIVE;
        }
    }
