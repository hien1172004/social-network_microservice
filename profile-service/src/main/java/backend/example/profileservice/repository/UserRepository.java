package backend.example.profileservice.repository;

import backend.example.profileservice.entity.UserProfile;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.neo4j.repository.Neo4jRepository;
import org.springframework.data.neo4j.repository.query.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends Neo4jRepository<UserProfile, String> {
    
    @Query("MATCH (u:user-profile {userId: $userId}) RETURN u")
    Optional<UserProfile> findByUserId(@Param("userId") String userId);

    Page<UserProfile> findAll(Pageable pageable);

    @Query(
            value = """
        MATCH (u:UserProfile)
        WHERE toLower(u.username) CONTAINS toLower($keyword)
           OR toLower(u.email) CONTAINS toLower($keyword)
           OR toLower(u.firstName) CONTAINS toLower($keyword)
           OR toLower(u.lastName) CONTAINS toLower($keyword)
        RETURN u
        SKIP $skip LIMIT $limit
    """,
            countQuery = """
        MATCH (u:UserProfile)
        WHERE toLower(u.username) CONTAINS toLower($keyword)
           OR toLower(u.email) CONTAINS toLower($keyword)
           OR toLower(u.firstName) CONTAINS toLower($keyword)
           OR toLower(u.lastName) CONTAINS toLower($keyword)
        RETURN count(u)
    """
    )
    Page<UserProfile> searchByKeyword(@Param("keyword") String keyword, Pageable pageable);


}
