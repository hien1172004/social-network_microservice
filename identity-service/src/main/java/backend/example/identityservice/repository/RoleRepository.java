package backend.example.identityservice.repository;

import backend.example.identityservice.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, String> {
}
