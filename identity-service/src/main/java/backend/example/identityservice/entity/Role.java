package backend.example.identityservice.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "roles")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Role {

    @Id
    private String name; // ROLE_USER, ROLE_ADMIN

    String description;
}
