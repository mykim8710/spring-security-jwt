package spring.security.jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import spring.security.jwt.domain.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);
}
